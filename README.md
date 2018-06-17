# Frick

Frick is a kick ass frida cli for reverse engineer inspired by the epic GDB init gef by @hugsy, with commands design similar to uDdbg.

![Alt text](https://image.ibb.co/kGqSfJ/Schermata_2018_06_17_alle_14_57_25.png "frick")

### WIPWIPWIP
* help command
* destruct command
* improve hexdump performance
* add more stuffs
* restart/cleanups command
* colorize everything

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

### TLDR;
It will hook all the given targets offsets, sleep the process and give you an interactive cli
which will allow you to do stuffs - including adding other targets - and of course - move to next.

### Get into the business
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