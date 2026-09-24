# Hiiragi-cast

A Python & Electron implementation of a Chromecast receiver. Works on Windows, macOS and Linux (Debian & arch).

This app uses [CastReceiver](https://play.google.com/store/apps/details?id=com.softmedia.receiver.castapp&hl=en_US) as a base and create a new receiver with a custom UI and additional features.

## How to use
1. Install [Python 3](https://www.python.org/downloads/) and [Node.js](https://nodejs.org/en/download/)
2. Use the command `python setup.py` to install the required Python packages, nodejs packages, setup EVS.
3. Use the command `python main.py` to restart the receiver after setup.

## What is working and not working
- Working:
    - Players that use the standard media player 
    - Youtube
    - Tab/desktop casting
    - DRM protected content
- Not working:
    - Players that use their own namespace (e.g. Spotify, Netflix, Disney+)