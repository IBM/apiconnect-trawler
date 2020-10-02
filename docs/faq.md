## Does trawler require a Cloud manager instance?

If you are running gateways/analytics separately to the manager components, trawler should be usable without the cloud manager in the cluster - you can turn off or remove the 'manager' section from the nets portion of the configuration. 

## Trawler requires a password to connect to the Datapower instance. Can I create a separate account for this?

Yes - I'm not sure what the privileges need to be - I need to get this figured out and documented - I notice at the moment I have a section in there that is attempting to enable statistics - which I need to remove and switch to check if it's enabled - trawler intent is to be read-only

## Does trawler require the Datapower REST API to be exposed?

Yes - this is how trawler is collecting the metrics.

## Do we have any more documentation on this project?

I intend to build this up gradually - there's no additional documentation yet, but I'm happy to take questions / suggestions either by e-mail or on the github repo. Hopefully then we can focus documentation on the areas that are most useful first. 
