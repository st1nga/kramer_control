#!/usr/bin/env python
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Listen to webapp socket and kramer unit so that we can control what it does.
#===========================================================================
# Modifications
# MP 27-Feb-2019
# Added looging to database and update which studio is current
#
# create table active_studio (
# id int(11) unsigned not null auto_increment,
# ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
# studio varchar(10) not null,
# source varchar(5),
# primary key (id),
# unique key (ts));
#
# MP 01-Mar-2019
# Added looging to database and update which studio is current when a button is pushed
#
# MP 01_Dec-2019
# Added mosquitto
#---------------------------------------------------------------------------

import paho.mqtt.client as mqtt
mqtt.Client.connected_flag = False
mqtt.Client.mqtt_result = 0
mqtt.Client.message = ''
mqtt.Client.logger = 0

import signal
import uuid
import time

import MySQLdb

import socket
import select
import logging
from optparse import OptionParser
import sys
import inspect

import configparser
import platform

import struct

button_pushed_txa = '\x41\x81\x81\x81'
button_pushed_txb = '\x41\x82\x81\x81'
button_pushed_tx3 = '\x41\x83\x81\x81'
button_pushed_ob = '\x41\x84\x81\x81'

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Stops nasty message going to stdout :-) Unrequired prettyfication
#---------------------------------------------------------------------------
def signal_handler(sig, frame):
  print("Exiting due to control-c")
  sys.exit(0)

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#---------------------------------------------------------------------------
def custom_logger(name, logger_level, config, log_to_screen):
    '''Custom logging module'''

    logger_level = logger_level.upper()

    formatter = logging.Formatter(fmt='%(asctime)s %(name)s:%(process)-5d %(levelname)-8s %(lineno)-4d: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S')

    handler = logging.FileHandler(config.get("kramer_control", "log_file"), mode='a')
    handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(logging.getLevelName(logger_level))
    logger.addHandler(handler)

    if log_to_screen == True:
      screen_handler = logging.StreamHandler(stream=sys.stdout)
      screen_handler.setFormatter(formatter)
      logger.addHandler(screen_handler)

    return logger

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#connect to mosquitto MQTT
#---------------------------------------------------------------------------
def connect_to_mosquitto(logger, config):

  mosquitto = mqtt.Client(client_id = "now_playing_pi_%s" % uuid.uuid4(), clean_session=True)
  mosquitto.username_pw_set(username = config.get("mqtt", "username"), password = config.get("mqtt", "password"))
  mosquitto.on_connect = on_connect
  mosquitto.on_subscribe = on_subscribe
  mosquitto.on_message = on_message
  mosquitto.on_disconnect = on_disconnect
  mosquitto.on_publish = on_publish
  mosquitto.connect(config.get("mqtt", "host"), int(config.get("mqtt", "port")))

  mosquitto.loop_start()

#+
#Loop until we have connected
#-
  while not mqtt.Client.connected_flag:
    time.sleep(0.1)

  return mosquitto

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Called when we sucessfully connect to mqtt broker
#---------------------------------------------------------------------------
def on_connect(mosquitto, userdata, flags, rc):

  mqtt.Client.mqtt_result = rc

  if mqtt.Client.mqtt_result == 0:
    mqtt.Client.connected_flag = True
    mqtt.Client.logger.debug("Connected sucessfully to Mosquitto")
  else:
    mqtt.Client.logger.debug("Bad mosquitto connection: %s"  % rc)

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Called when we sucessfully subscribe to a topic
#---------------------------------------------------------------------------
def on_subscribe(client, userdata, mid, granted_qos):

  mqtt.Client.logger.debug("We have subscribed")

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Called when we receive a message from mqtt
#---------------------------------------------------------------------------
def on_message(client, userdata, message):
  mqtt.Client.logger.debug("Got a message '%s'" % str(message.payload.decode("utf-8")))
  mqtt.Client.message = str(message.payload.decode("utf-8"))
  mqtt.Client.logger.debug(mqtt.Client.message)

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# on_disconnect
#---------------------------------------------------------------------------
def on_disconnect(client, userdata, rc):
  mqtt.Client.logger.debug("Unexpected disconnection")

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#on_publish callback for mosquitto
# Gets called once we have published (?maybe)
#---------------------------------------------------------------------------
def on_publish(client, userdata, mid):
  mqtt.Client.logger.debug("Published message")

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#publish_to_mosquitto MQTT
#---------------------------------------------------------------------------
def publish_to_mosquitto(mosquitto, topic, metadata_to_send, logger):

  (result, mosquitto_id) = mosquitto.publish(topic, metadata_to_send, qos=1, retain=True)
  logger.debug("Metadata sent to mosquitto:%s. Result = %s" % (topic, result))

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#---------------------------------------------------------------------------
def status_check(socket):
    status_msg = "\x05\x80\x81\x81"
  
    socket.send(status_msg)
    status_data = ""
    while len(status_data) < 4:
        status_data = "%s%s" % (status_data, socket.recv(1024))

#    print " ".join(hex(ord(n)) for n in status_data)
    if status_data == '\x45\x80\x81\x81':
        return "txa"
    elif status_data == '\x45\x80\x82\x81':
        return "txb"
    elif status_data == '\x45\x80\x83\x81':
        return "tx3"
    elif status_data == '\x45\x80\x84\x81':
        return "ob"
    else:
        return "error"

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Send the fact we have changed studios to info zone
#---------------------------------------------------------------------------

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# When we change studio log the fact to the DB
#---------------------------------------------------------------------------
def update_active_studio(studio, logger, source, config, mosquitto):
#+
#Need to connect to DB
#-
    try:
        db = MySQLdb.connect(host=config.get('mysql', 'host'), user=config.get('mysql', 'user'), passwd=config.get('mysql', 'passwd'), db=config.get('mysql', 'db'))
    except MySQLdb.Error as err:
        logger.error("Error %d: %s" % (err.args[0], err.args[1]))
        sys.exit(1)

    cursor = db.cursor();

    sql = "insert into active_studio (studio, source) values ('%s', '%s')" % (studio, source)
    logger.info(sql)

    try:
        cursor.execute(sql)
        db.commit()
    except MySQLdb.Error as err:
        logger.error("Error %d: %s" % (err.args[0], err.args[1]))
        sys.exit(1)

    db.close()

#+
#Publish message to mosquitto
#-
    publish_to_mosquitto(mosquitto, 'pi/active_studio', studio, logger)

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#---------------------------------------------------------------------------
def switch_to(socket, channel, studio, logger, source, mosquitto):
    socket.send(channel)

    status_data = ""
    while len(status_data) < 4:
        status_data = "%s%s" % (status_data, socket.recv(1024))

    logger.info("calling update_active_studio")
    update_active_studio(studio, logger, source, mosquitto)

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# main Main MAIN
#---------------------------------------------------------------------------
def main():

    read_list = []

#+
#Catch control-c
#-
    signal.signal(signal.SIGINT, signal_handler)

#Parse the options passed
    parser = OptionParser()
    parser.add_option("", "--logger-level", dest="logger_level",
                      help="Log level: ERROR, WARNING, INFO, DEBUG [Default=%default]", default="INFO")
    parser.add_option("", "--log-to-screen", action="store_true", dest="log_to_screen",
      help="Output log message to screen [Default=%default]", default=False)

    parser.add_option("", "--config", dest="config_file",
      help="Config file [Default=%default]", default="/etc/kramer_control.conf")

    (options, args) = parser.parse_args()

#+
#Load the config file
#-
    config = configparser.ConfigParser()
    config.read(options.config_file)

#+
#Setup custom logging
#-
    logger = custom_logger(config.get('kramer_control', 'logger_name'), options.logger_level, config, options.log_to_screen)
    mqtt.Client.logger = logger
    logger.info("Hello world! Python version = '%s'" % platform.python_version())

#+
#Connect to mosquitto, the MQTT broker
#-
    mosquitto = connect_to_mosquitto(logger, config)

#bind to port so that we can accept commands from webpage
    webapp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    webapp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        webapp_socket.bind(('0.0.0.0', 8000))
    except socket.error as err:
        logger.error("Error 0.0.0.0:8000: %d: %s" % (err.args[0], err.args[1]))
        sys.exit(1)

    webapp_socket.listen(1)
    read_list.append(webapp_socket)

#Connect to krammer switch so we can control and listen
    kramer_socket = socket.socket()
    kramer_socket.connect((kramer_ip,kramer_port))

    read_list.append(kramer_socket)

#+
#Get inital status of kramer switch and write to DB
#-
    kramer_status = status_check(kramer_socket)
    if kramer_status == 'error':
        logger.error("Initial Status fuck up... oops! Exiting")
        exit(1)

    logger.info("Initial Status says %s is active" % kramer_status)
    update_active_studio(kramer_status, logger, 'startup', config, mosquitto)

#Loop forever
    while True:
#Get the status of the kramer switcher, check for fuck as well.
        kramer_status = status_check(kramer_socket)
        if kramer_status == 'error':
             logger.error("Status fuck up... oops! Exiting")
             exit(1)
        else:
            logger.info("Status says %s is active, Waiting for input..." % kramer_status)

#wait until a port is readable
        readable, writable, exceptional = select.select(read_list, [], read_list)

        for sock in readable:
#If it is kramer that is readable then someone has pushed a button
            if sock is kramer_socket:
                logger.info("Button pushed on kramer switcher")

                kramer_data = ""

#Get data until we have 4 bytes
                while len(kramer_data) < 4:
                    kramer_data = "%s%s" % (kramer_data, kramer_socket.recv(1024))

#We have 4 bytes of data

                if kramer_data == button_pushed_txa:
                   update_active_studio("txa", logger, 'kramer', config, mosquitto)
                elif kramer_data == button_pushed_txb:
                   update_active_studio("txb", logger, 'kramer', config, mosquitto)
                elif kramer_data == button_pushed_tx3:
                   update_active_studio("tx3", logger, 'kramer', config, mosquitto)
                elif kramer_data == button_pushed_ob:
                   update_active_studio("ob", logger, 'kramer', config, mosquitto)


#New connection from webapp
            elif sock is webapp_socket:
                connection, address = webapp_socket.accept()
                logger.info("Connection from %s, %s" % (address))
                read_list.append(connection)

#Only thing left is data from webapp
            else:
                data = sock.recv(1024).rstrip()
                if not data:
                    logger.info("%d: webapp fuck up 1" % lineo())
                else:
                    logger.info("Data from API = %s" % data)
##See if we have a ':', if we split into 2 fields 1st = studio, 2nd = source of command
                    source = ""
                    if (data.find(':') != -1):
                      logger.info("We found a colon")
                      data_split = data.split(':')
                      logger.info("Studio=%s, from=%s" %(data_split[0], data_split[1]))
                      data = data_split[0]
                      source = data_split[1]

                    if data == "txa":
                        switch_to(kramer_socket, '\x01\x81\x81\x81', "txa", logger, source, mosquitto)
                    elif data == "txb":
                        switch_to(kramer_socket, '\x01\x82\x81\x81', "txb", logger, source, mosquitto)
                    elif data == "tx3":
                        switch_to(kramer_socket, '\x01\x83\x81\x81', "tx3", logger, source, mosquitto)
                    elif data == "ob":
                        switch_to(kramer_socket, '\x01\x84\x81\x81', "ob", logger, source, mosquitto)
                    elif data == "status":
                        sock.send(kramer_status)
                sock.close()
                read_list.remove(sock)


if __name__ == "__main__":
#    exit()
    main()
