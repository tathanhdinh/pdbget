# pdbget

A small tool for downloading Program DataBase (PDB) of PE files.

## Usage

```
pdbget.exe --help
pdbget 0.1.0
TA Thanh Dinh <tathanhdinh@gmail.com>
Download PDB (Program DataBase) files from a symbol server

USAGE:
    pdbget.exe [FLAGS] [OPTIONS] <PE files>... --server <Symbol server>

FLAGS:
    -v, --verbose    Verbose mode
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -o, --output <Output folder>    Location for downloaded PDB(s) (default: current folder)
    -s, --server <Symbol server>    URL of the symbol server (e.g. https://msdl.microsoft.com/download/symbols/)

ARGS:
    <PE files>...    Input PE file(s)
```

## Examples
- Download PDBs from Microsoft's symbol server

```
pdbget.exe c:\windows\system32\**\* -s https://msdl.microsoft.com/download/symbols -o pdbs
```

<img src="https://github.com/tathanhdinh/pdbget/blob/master/screenshots/microsoft.gif?raw=true">

- Download PDBs from Mozilla's symbol server

```
pdbget.exe "C:\Program Files\Mozilla Firefox"\**\* -s https://symbols.mozilla.org/ -o pdbs -v
```

<img src="https://github.com/tathanhdinh/pdbget/blob/master/screenshots/mozilla.gif?raw=true">

- Download PDBs from Google's symbol server

```
pdbget.exe "C:\Program Files (x86)\Google\Chrome\Application\63.0.3239.132"\**\* -s https://chromium-browser-symsrv.commondatastorage.googleapis.com/ -o pdbs -v
```
<img src="https://github.com/tathanhdinh/pdbget/blob/master/screenshots/google.gif?raw=true">