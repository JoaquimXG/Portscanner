#!/bin/python3

class interface:
    """Used to hold all the attributes of the interfaces of the current host"""

    def __init__(self,IP,MAC,name):
        self.IP=IP
        self.MAC=MAC
        self.name=name

    def __str__(self):
        return "<Instance of class.interface {}>".format(self.IP)
    def __repr__(self):
        return "<Instance of class.interface {}>".format(self.IP)

class target:
    """used to hold the attributes of each target specified by the user"""

    def __init__(self,IP):
        self.IP=IP
        self.is_up=False

    def __str__(self):
        return "<Instance of class.targets {}>".format(self.IP)
    def __repr__(self):
        return "<Instance of class.targets {}>".format(self.IP)
