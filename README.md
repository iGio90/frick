# Frick

Frick is a kick ass frida cli for reverse engineer inspired by the epic GDB init gef by @hugsy, with commands design similar to uDdbg.

![Alt text](https://image.ibb.co/kGqSfJ/Schermata_2018_06_17_alle_14_57_25.png "frick") 

![Alt text](https://preview.ibb.co/eXYvkJ/Schermata_2018_06_17_alle_18_49_07.png "frick")


### Features for the eyes
* interactive commands with shortcuts 
* nice ui and colors (thanks @hugsy)
* commands history
* save/load previous target offsets and target to attach and work in less then a second

### Good stuffs
* custom hexdump highlighting pointers and values
* pointer recursion on registers display
* allow to store vars that can be the result of a command (see examples later)
* commands arguments evaluation (see examples later)
* command ``destruct`` should be really helpful while reversing structs (see screenshot later)

##### checkout the [complete commands list](./COMMANDS.md)


### TLDR;
It will hook all the given targets offsets, sleep the process and give you an interactive cli
which will allow you to do stuffs - including adding other targets - and of course - move to next.

### Get into the business

```
# run 
git clone https://github.com/iGio90/frick
cd frick
python main.py
```

```
-> frick started - GL HF!
add 0x017BA150 my pointer 1
-> 0x17ba150 added to target offsets
add 0x017BB68C my other target
-> 0x17bb68c added to target offsets
add 0x017BB7A8 one more
-> 0x17bb7a8 added to target offsets
attach com.package libtarget.so
-> frida attached
-> script injected
-> target arch: arm
-> target base at 0xc4af2000
-> attached to 0xc62ac150
-> attached to 0xc62ad7a8
-> attached to 0xc62ad68c
s save
-> session saved

# next time we run frick, we can just do 's load' 
# to load the same target and attach to the same offset
```

An example of command within the context could be:

``memory read 0x1000 128``

this will read 128 bytes at 0x1000.

The same result can be achieved with:

``m r 0x1000 128``

``mem r 0x1000 64+64``

all the arguments are evalueted with my logic - which could be bad. feel free to improve.

Once in a contex - the placeholder **$** can be used to point to a register value - I.E:

``memory read $r0 128``

will read 128 bytes in pointer value held by r0.

in addition to this, it's possible to store variables.

``a = 10 + 10``

``print a + $r0``

will print 20 + the value held by r0.

Variables can be also generated with the result of a command - I.E:

``m r ptr $r0``

will read a pointer in the memory address pointed by the value held in r0. So we can do:

``myptr = memory read pointer $r0``

myptr will now be a value which can be used freely in args:

``m r myptr 128``

``print myptr + $r0 + $r1 << 32``

## Screenies

##### destruct

Read arg1 bytes in pointer arg0. Then, recursively read all the pointers in that range for depth in arg2 (default 32 divided by 2 each recursion until < 8).
This should be extreme helpful to highlight structures and arrays of objects.

![Alt text](https://image.ibb.co/iaOgQJ/Schermata_2018_06_17_alle_23_23_06.png "frick")
