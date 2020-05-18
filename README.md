# spotify_deduplicator

Small project to detect duplicated playlist names for a given username.

I maintain a large backlog of albums as Spotify playlists. This project is aimed at helping me detect duplicated playlist names even in the presence of small differences. 

At the moment the application uses client credentials. That means that we can only get public playlists.

The script requires a `config.json` file. A template is provided as `config.json.template`.
