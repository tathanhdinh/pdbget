# pdbget

A small tool for downloading Program DataBase (PDB) of PE files.

## Usage

```
pdbget --help

USAGE:
    pdbget [OPTIONS] <input> --server <url>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -o, --out <output>    Directory to save downloaded pdbs (default: current)
    -s, --server <url>    Symbol server url (e.g. https://msdl.microsoft.com/download/symbols/)

ARGS:
    <input>    PE file or folder (recursively traversed)
```

## Example
- Download PDBs of Microsoft Windows system dlls

```
pdbget windows_dlls/ -o pdbs -s https://msdl.microsoft.com/download/symbols/
```

<img src="screenshots/windows_dlls.gif?raw=true">

<!-- ```
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
<img src="https://github.com/tathanhdinh/pdbget/blob/master/screenshots/google.gif?raw=true"> -->