# DLL Proxying

<<<<<<< HEAD
This code runs a C# assembly from a C/C++ DLL Proxy. Originally made for the Conjure Project.
=======
Conjure uses DLL Proxying in order to automatically run the program on the workstations. We plant a fake Dynamic-Link Library in System32 that will hook functions to a DLL and run the Conjure code.
>>>>>>> 69018586008d7afd5dde94bbb2bce77075c712a7

## Usage

### Creating the DLL
 - Write and properly edit the DLL using the C++ template.

 - Obtain export functions from target DLL using ```getExports.py```

```bash 
$ python3 getExports.py <target DLL>
```

 - Append the output of ```getExports.py``` to the end of the the DLL file and compile 

 - Plant proxy DLL under the original name and location