# DLL Proxying

Disables ETW and runs C# assembly from a C/C++ DLL Proxy.

## Usage

### Creating the DLL
 - Write and properly edit the DLL using the C++ template.

 - Obtain export functions from target DLL using ```getExports.py```

```bash 
$ python3 getExports.py <target DLL>
```

 - Append the output of ```getExports.py``` to the end of the the DLL file and compile 
