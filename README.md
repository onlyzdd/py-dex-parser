# Android DEX file parser using Python

This repository contains and example for parsing Android Dex file using Python.

## Requirements

- Python3: run main code
- Apktool: generate smali code

## Run

```sh
$ unzip data/apk/abcore.apk -d data/unzipped/abcore # extract dex files
$ apktool d data/apk/abcore.apk -o data/smali/abcore # generate samli code (not required)
$ python main.py # run main code to extract strings, types, protos, fields, methods, classes from DEX file
```

## Reference

- [DEX Binary Template](./DEX.bt)
- [Python Struct](https://docs.python.org/3/library/struct.html)
- [Apktool](https://ibotpeaches.github.io/Apktool/)
- [Smali](https://github.com/JesusFreke/smali)
