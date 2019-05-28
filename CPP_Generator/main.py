#!/usr/bin/env python3
from ScriptBody import executableGenerator
import inspect


def main():
    data = executableGenerator(domain="CONSTOSO.com", domainUser="CONSTOSO.com\\justin", domainPassword="SOMEPASS")

    for item in inspect.getmembers(data):
        if not item[0].startswith(('_', 'w')) and not item[0] == 'scriptBody':
            if not inspect.ismethod(item[1]):
                print(item)

    
    proceedVariable = input('Continue?: ').upper()
    
    if any(proceedVariable.upper() == item.upper() for item in ['yes', 'y']):
        with open('file.cpp', 'w') as file:
            file.write(data.scriptBody)
            file.close()
    else:
       exit(0)


if __name__ == '__main__':
    main()