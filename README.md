# kramer_control
Code to control a Kramer switch unit, specifically a Kramer VP-23N.

I chose the VP-23N as it was network enabled making it easier to control.

The VP-23N accepts balanced audio inputs, this allows CoastFM to switch studios by either using the physical buttons on the unit or via a network connected device.
We have a web page and can also switch by VOIP control.

Previously we had a VS-4X for switching but this did not allow for remote switching IE someone had to be in the studio to do the switch and this hampered doing outside broadcasts as we needed someone in the studio to do the switch.

This python script listens on a port for external switch requests and also listens to the Kramer VP-23N , The VP-23N spits out data when physical switching happens on the unit.

We can then track the data, update various screens and log to the database that a switch has happened.

I need to add a sub studio switching process.
We use openob OB, so I can switch this on and off
With C19 we have a lot of homebased presenters they are remote studios, I am going to hang this of the OB switch option and only have one openob process running at a time.

So a process on each OB unit to stop/start openob if it is the active OB
A process on the reciever (tantive) to stop/start the openob receiver
Update the switch page.
