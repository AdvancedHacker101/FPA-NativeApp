# FPA-NativeApp
This is the application running on your PC used for fpa or *Fingerprint Authentication*.  
This application is required for the fpa protocol to work.  
This application is the middle man of your authentications, it needs to be on the same network as the phone is.  
The application works together with the [Phone App](https://github.com/AdvancedHacker101/FPA-PhoneApp)  
It provides features like:
* Logging in to windows with your fingerprint
* Logging in to website with your fingerprint

Also support is coming for website owners to implement the fpa protocol with **2FA** so you can use your fingerprint as a 2nd factor of authentication.
## Installation
This project is in development stage, so regular users may check back later for status updates. But you're feel free to install it.
Follow these steps: 
1. Fork the project
2. Open up the project with visual studio
3. Press the green `Start` button or press `F5`

That's it, the application is now running.

## Usage
Yeah the UI is ugly, that's part of why this project is in development stage :)  
You can test out windows authentication, and website authentication with [FPA Browser Extension](https://github.com/AdvancedHacker101/FPA-Extension)  
**Note**: Windows authentication form can be bypassed multiple ways, this is for debugging purposes, as you don't want to permanently lock you machine.  
If you wish to enable protection features edit the following files:
* In LockUI.cs at the top of the file  
  * Change `#define SafetyButton` to `#undef SafetyButton`, this will remove the safety close button from the login form
  * Change `#define ForceTopDisable` to `#undef ForceTopDisable` this will enable the form to constantly stay on top of every other window
* In WindowsLocking.cs at the top of the file
  * Change `#define ProcLockDisable` to `#undef ProcLockDisable`, this will launch a protector process (more on this below)
  
Similar to this if you want to disable a protection you can change the `#undef` prefix to `#define`.  
### Process Locking
After locking the PC the app starts another process, it's only purpose is to check if the parent process died and restart it if it did.  
Similar to this the parent process also looks out for the child/protector process. So if the protector process dies, it gets restarted by the parent process.  
This prevents the bypassing of the locking by killing the locking process.  
### Default authentication (Devs)
I didn't find any ways to replace the default windows authentication process. Even if I found one the windows login process loads user settings/user registry after logging in which needs to be handled by my application in case of replacement.  
If you know an easier/possible way to replace the default authentication open an issue ASAP!
## Development notes
* It's not visible in the UI but there's a feature which adds the lock mechanism to the autostartup registry key, this is under testing
* Accepting the firewall prompt is required to open up a server for the android application to connect to
* To reset the windows authentication key locate the folder of the exe file and delete the file named `logon.hash`
