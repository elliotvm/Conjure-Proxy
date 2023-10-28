'''
    Create exports for every function of a given DLL
    https://sh0ckfr.com/pages/martin-et-le-dll-proxying-de-cristal/
    change pe and proxy to desired DLL
'''

import pefile

target = "C:\\windows\\system32\\dnsapi.dll"              #DLL TO EXTRACT FUNCTIONS FROM
proxy = "C:\\\\windows\\\\system32\\\\utilitycore.dll"    #DLL TO EXPORT FUNCTIONS TO

pe = pefile.PE(target)

exported_functions = []

for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
	func = entry.name.decode('utf-8')
	exported_functions.append(f'#pragma comment(linker,"/export:{func}={proxy}.{func},@{entry.ordinal}")')

exported_functions = '\n'.join(exported_functions)
print(exported_functions)