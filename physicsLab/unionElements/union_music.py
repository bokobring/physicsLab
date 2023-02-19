#coding=utf-8
from electricity import *
from math import sqrt, ceil

from physicsLab import *

'''
How do you play music in physics Lab AR?
Music extension might make it easier than before!

    How to use it?
>>> music(a_list_or_a_tuple)
>>> write_Experiment()
Then, enjoy your music at physics Lab AR!

    What is the format of the music array?
The format of music array compat netlogo music list(ml) which was used by Li Weijia at Turtle Lab.
（但在兼容李维嘉的ml乐谱之前，我可能会先做一套自己设计的精简版btlist）
'''

# 只支持钢琴的初代版本
'''
输入格式：
[
    [一些音符，每次会同时演奏这些音符],
    [一些音符，每次会同时演奏这些音符]
] # 元组也可以
'''
class union_music:
    def __init__(self, x: Union[int, float] = 0, y: Union[int, float] = 0, z: Union[int, float] = 0, musicArray: Union[list, tuple] = ()):
        tick = Nimp_Gate(x, y + 0.1, z)
        crt_wire(Logic_Input(x, y, z).o, tick.i_up), crt_wire(tick.o, tick.i_low)
        crt_wire(tick.o, Counter(x + 0.2, y, z).i_up)
        side = ceil(sqrt(musicArray.__len__()))
        pass