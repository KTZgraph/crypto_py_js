"""
For multiple calling function with list of arguments
@parametrized from lib parametrized is not compatible in Python3
Args:
    List of list of arguments for function
Usage:
>>> l = [[2,3], [6,7,], [8,9], [12,34]]
>>> @expand(l)
>>> def add(a, b):
>>>     print("a: ", a)
>>>     print("b: ", b)
>>>     return a+b
>>> add()
"""


def expand(arglist):
    def decorator(func):
        def wrapped_function(*args, **kwargs):
            for arg in arglist:
                func(*arg)
        return wrapped_function
    return decorator


if __name__ =="__main__":
    a = [2,3]
    b = [6,7]
    c = [8,9]
    d = [12,34]

    arglist = []
    arglist.append(a)
    arglist.append(b)
    arglist.append(c)
    arglist.append(d)


    @expand(arglist)
    def add(a, b):
        print("a: b:", a, b)
        print("Wynik: ", a+b)
        return a+b

    add()