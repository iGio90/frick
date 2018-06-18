Knowing how simple is to add or mod a command is key for 2 reasons:
* you can improve what i've did
* you can create your own commands and logics

Command class is as simple as we see it:

```python
class Command(object):
    def __init__(self, cli):
        self.cli = cli

    def get_command_info(self):
        return None
```

here is an example of simple command:

```python
class MyCommand(Command):
    def get_command_info(self):
        return {
            'name': 'mycommand',
            'info': 'mycommand desc',
            'args': 1 # minimum args
        }

    def __dosomething__(self, args):
        do_some_cool_stuffs(args)
        return None
```

Something to note:
* the function invoked will always be __ cmdname __
* args is the array of arguments without command (pure args)
* args are evaluated

The next step would be add shortcuts and subcommands

```python
class Add(Command):
    def get_command_info(self):
        return {
            'name': 'mycommand',
            'info': 'mycommand desc',
            'args': 1, # minimum args
            'shortcuts': [
                'myc', 'mc'
            ],
            'sub': [
                {
                    'name': 'mysubcommand',
                    'info': 'subc info',
                    'shortcuts': ['sbc', 'sb']
                }
            ]
        }

    def __dosomething__(self, args):
        do_some_cool_stuffs(args)
        return None
        
    def __mysubcommand__(self, args):
        print('hey im in the subcommand')
```

things to note:
* the cli will accept any of ``myc mysubcommand args`` ``mycommand sbc args`` etc
* sub can have sub which can have sub with the same structure

Once you have this - the last thing to know is about the other 2 method which can be optionally created inside commands.

Assuming we still have our previous code, with our ``dosomething`` command in place, we can add:

```python
    def __dosomething_result__(self, result):
        self.cli.hexdump(result)

    def __dosomething_store__(self, data):
        return data + 10      
```

the first one ``_result__`` will be invoked with the result of our ``__dosomething__`` if it returned something that is not ``None``. It's good practice to return whatever data and then print it (if needed) in the ``_result__``.

This, because of the other feature of Frick, storing args.
Creating a command will also give the ability to do something like:

```
myvar = dosomething 0x1000
```

if dosomething return a valid value, then myvar will be that value. Here comes in action the ``_store__``.
when we are attempting to store a value, then ``_store__`` will be invoked, if any, before storing the data, allowing for final modifications.

Taking an existing command as example:

```python
    def __read__(self, args):
        try:
            return [args[0], self.cli.frida_script.exports.mr(args[0], args[1])]
        except Exception as e:
            log('failed to read data from device: %s' % e)
            return None

    def __read_result__(self, result):
        self.cli.hexdump(result[1], result[0])

    def __read_store__(self, data):
        return data[1]
```