A tool to dump Oslo bysykkel availability data to later create dashboards

Runs out of a cron job

Example Configuration
```
* * * * * . /path/to/env/.profile; /usr/bin/ruby -C /path/to/oslocitybike-history dump.rb >> /path/toe/oslocitybike-history_cron.log 2>&1
```

Requires a BYSYKKEL_TOKEN
