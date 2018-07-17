# binaryninja-vle
A disassembler and lifter for the PowerPC Book E Variable Length Encoding extensions

# to install:
This plugin relies on the libvle

1) Have git pull the libvle code:
```
$ git submodule init; git submodule update
```

2) Next, compile libvle:
```
$ cd libvle
$ make
$ cd ..
```

3) Finally, link or copy this folder into the BinaryNinja plugins folder.  On my system:
```
$ cd ~/.binaryninja/plugins
$ ln -s </path/to/binaryninja-vle> 
```

4) Done!

