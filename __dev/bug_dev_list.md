## [bug]
- playwright not starting
- for amass enum, the IP and AS columns should be populated but they're not at the moment. also popuplate the IPs file. 


## [dev]
- we don't need the scope entries section since we can just open the files

- for the subdomain enumeration part when it starts, we could make a progress bar below the checkpoint item so at least we can see for example how much wildcards are already processed, etc. we just don't sit here blindly for hours not knowing what's happening, you know. 

- we need to make sure that ever projectd data goes into the data folder, so we segment the data findings etc, from the application logic. rn robots is a different folder, dorking, fuzzing, logs... etc etc. so basically the data folder should containt everytning that comes from the automations and such. 
- put an export button for every file up next to the close button. export will download the given file. 