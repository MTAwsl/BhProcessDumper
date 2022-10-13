# ProcessDumper

## Introduction
This project is intended to dump all pages in a running process. Run on Windows only.

## Usage
```
BhProcessDumper [-h] [--name VAR] [--pid VAR] [--output VAR]

Optional arguments:
  -h, --help    shows help message and exits
  -v, --version prints version information and exits
  -n, --name    Name of the target process.
  -p, --pid     PID of the target process.
  -o, --output  Output file name.
```
If you provided -p and -n at once, the -n would be ignored.

## Generated file
The generated file's format could be found in filestruct.h.
By implementing more features on DumpAnalyzer, which is an example for analyzing the dump file, it would flexibly dealing with dump files.
For example, the analyzer could restore the memory environment of the process or help to do some forensic works...