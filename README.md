# DLL Proxying

Conjure uses DLL Proxying in order to automatically run the program on the workstations. We plant a fake Dynamic-Link Library in System32 that will execute the Conjure code when called and proxy every function to the real DLL.

## Usage

### Choosing target DLL

 - Choose a DLL that gets loaded at startup by default in Windows

 - Conjure targets ```dnsapi.dll``` by default

### Creating the DLL
 - Write the DLL using the C++ template or Visual Studio solution, change location of the program to run in ```system()``` call

 - Obtain export functions from target DLL using ```getExports.py```
    - Make sure to change ```pe``` and ```proxy```

```bash 
$ python3 getExports.py <target DLL>
```

 - Append the output of ```getExports.py``` to the end of the the DLL file and compile 

### Planting the DLL
 - Duplicate/rename real DLL to hidden location (Same location that ```proxy``` points to) 
    - Ex. System32\dnsapi.dll -> System32\utilitycore.dll 
    - In order to obtain permission to change a file in System32, use: Properties > Security > Advanced > Change Permissions > username > Apply > Change Permission for Group
    - Switch files back to original permissions when finished

 - Plant proxy DLL under the original name and location
 - Restart Machine
