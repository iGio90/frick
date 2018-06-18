# Commands list
|   command   |              short              |                                        info                                         |
|-------------|---------------------------------|-------------------------------------------------------------------------------------|
|  add        |                                 |  add offset from base 0x0 in arg0 with optional name for this target in other args  |
|  attach     |  att                            |  attach to target package name in arg0 with target module name in arg1              |
|  backtrace  |  bt                             |                                                                                     |
|  destruct   |  des,ds                         |  read at address arg0 for len arg1 and optional depth arg2                          |
|  find       |  f,fi                           |  utilities to find stuffs                                                           |
|  help       |  h                              |                                                                                     |
|  hexdump    |  hd,hdump                       |  a shortcut to memory read command                                                  |
|  info       |  i,in                           |  get information about your target                                                  |
|  memory     |  m,mem                          |  memory operations                                                                  |
|  print      |  p,pr                           |                                                                                     |
|  quit       |  q                              |                                                                                     |
|  registers  |  r,reg,regs                     |  interact with registers                                                            |
|  run        |  c,cont,continue,go,next,start  |  continue the execution of the process to the next target offset                    |
|  session    |  s,ss                           |                                                                                     |

---
# find sub commands
|  command  |   short    |                                info                                 |
|-----------|------------|---------------------------------------------------------------------|
|  export   |  e,ex,exp  |  find export name arg0 in target module or in optional module arg1  |

# info sub commands
|  command  |        short         |                         info                         |
|-----------|----------------------|------------------------------------------------------|
|  modules  |  module,mod,mo,md,m  |  list all modules or single module in optional arg0  |
|  ranges   |  range,r,rg          |  list all ranges or single range in optional arg0    |

# memory sub commands
|  command  |  short  |                             info                             |
|-----------|---------|--------------------------------------------------------------|
|  alloc    |  a,al   |  allocate arg0 size in the heap and return the pointer       |
|  read     |  rd,r   |  read bytes from address in arg0 for len in arg1             |
|  write    |  wr,w   |  write into address arg0 the bytes in args... (de ad be ef)  |

# registers sub commands
|  command  |  short  |                  info                   |
|-----------|---------|-----------------------------------------|
|  write    |  wr,w   |  write in register arg0 the value arg1  |

# session sub commands
|  command  |  short  |                                           info                                           |
|-----------|---------|------------------------------------------------------------------------------------------|
|  save     |  s,sv   |  saves current target offsets, package and module to be immediatly executed with 'load'  |
|  load     |  l,ld   |  load session from previously saved information                                          |

---
# memory read sub commands
|  command  |  short  |                 info                  |
|-----------|---------|---------------------------------------|
|  pointer  |  p,ptr  |  read a pointer from address in arg0  |

