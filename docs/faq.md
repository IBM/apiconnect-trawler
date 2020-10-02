## Does trawler require a Cloud manager instance?

If you are running gateways/analytics separately to the manager components, trawler should be usable without the cloud manager in the cluster - you can turn off or remove the 'manager' section from the nets portion of the configuration. 

## Trawler requires a password to connect to the Datapower instance. Can I create a separate account for this?

Yes, a specific account can be specified for trawler to use.  The intent is for trawler to only need read-only access, however currently there it is also attempting to enable statistics - which needs to be switched to check for statistics - [issue](https://github.com/IBM/apiconnect-trawler/issues/4).

## Does trawler require the Datapower REST API to be exposed?

Yes - this is how trawler is collecting the metrics.

## Do we have any more documentation on this project?

I intend to build this up gradually - there's no additional documentation yet, but I'm happy to take questions / suggestions either by e-mail or on the github repo. Hopefully then we can focus documentation on the areas that are most useful first. 
