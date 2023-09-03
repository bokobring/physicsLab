﻿# physicsLab 物实程序化

[English](./README_en.md)

![输入图片说明](./cover.jpg)

## 介绍
在物理实验室做实验的时候，我们可能会苦恼于元件不够整齐，需要重复的搭建某些电路且重复地做测，或元件无法浮空等问题。这些问题都可以通过改存档来轻易解决！然而，手动改存档操作麻烦且出错率高。于是我写了```physicsLab```，并在其中封装了一些常用功能，让你用```Python```也能够轻易地在物实做实验，而且***你甚至不需用知道存档在电脑的哪里！***

## 安装教程

1.  请确保你的电脑有[Python](https://www.python.org)（大于等于3.6）与[物理实验室PC版](https://www.turtlesim.com/)（也可以联系[开发者Jone-Chen](https://gitee.com/civitasjohn)）
2.  在cmd或shell输入：
```shell
pip install physicsLab
```
3.  有一个并非必需的功能：播放midi。你可以输入下面命令的任意一条：
```shell
pip install plmidi
pip install pygame
```
之所以没有做安装physicsLab的时候自动安装这两个库，是因为安卓的`qpython`在下载含c的库的时候存在问题  
4.  如果你等不及使用一些新功能的话，测试版通常在gitee可以找到

### 新手解惑: 为什么我明明安装了physicsLab, python却告诉我无法找到？
pip安装的包会被放在site-package文件夹下  
这大概率是因为pip安装的包所对应的site-package与你使用的python对应的site-package不一样导致的  
解决方案：找到ide调用的python对应的site-package，然后把physicsLab与physicsLab.egg-info复制过去  
同时我推荐去学一下python的虚拟环境`venv`，有效解决此问题  
  
如果此方法失效了，虽然这一定不是这个方法的问题，但你还可以在python的开头写上这两行代码来解决这个问题：  
```python
import sys
sys.path.append("your physicsLab's path") # 将字符串替换为你想添加的路径
```
这个方法很丑陋但很简单好用，可以帮你快速解决问题，毕竟能跑起来就很不错了   
其原理是python会在sys.path这个列表里面的路径去寻找python package，若未找到则会报错。因此该方法的原理就是把python找不到的路径加进去，python就找到了   
注：每次运行的时候加入的path都是临时的，因此该方法必须让python在每次运行的时候都执行一遍   


## 开发环境
Windows7: python 3.7.8  &&  python 3.8.10  
Android: qpython(app) 3.11.4  
目测对其他版本支持应该也很好  
python3.6及以上应该没问题

## 使用说明
*目前```physicsLab```在```windows```上的支持最好，在```Android```上仅支持手动导入/导出存档（默认在```physicsLabSav```文件夹中）。**暂不支持其他操作系统***  

下面给出一个简单的例子（该例子仅用于讲解，你大概率无法运行）：
```Python
from physicsLab import *

  # 打开存档
open_Experiment("在物实保存的本地存档的名字")
  # 例：open_Experiment('测逝')
  # 也支持输入存档的文件名（也就是xxx.sav）
  # 如果你希望程序不覆盖掉存档中已有的实验状态，需要这样写
read_Experiment()
  # 创建一个逻辑输入，坐标为(0, 0, 0.1)
Logic_Input(0, 0, 0.1)
  # 你也可以不写坐标，默认是(0,0,0)，请注意2原件的坐标不允许重叠！
o = Or_Gate()
  # 此时o存储的是orGate的self
  # 元件含有引脚属性，是对物实原始的引脚表示方法的封装
  # 比如或门（Or_Gate），含有 i_up, i_low, o三个引脚属性
  # 通过引脚属性，就可以更方便的连接导线了

  # crt_Wire()函数用来连接导线，有三个参数：SourcePin, TargetPin, color
  # SourcePin与TargetPin必须传入元件的引脚
  # color可有可无，默认为蓝色
crt_Wire(o.i_up, o.i_low)
  # 将程序中生成的原件，导线等等写入存档
write_Experiment()
  # 然后用物实打开存档见证奇迹
```

```physicsLab```还支持功能相同但更优雅的方式：
```python
from physicsLab import *

with experiment('测逝', read=True):
    Logic_Input(0, 0, 0.1)
    o = Or_Gate()
    o.i_up - o.i_low # 连接导线
```
上面两段代码产生的结果是一样的  
  
更详细的内容请在[Doc](./Doc)中查看  
请注意：由于`physicsLab`使用中文注释并出现过编码问题，因此physicsLab有一套确保编码为`utf-8`的机制  
此时你可以手动在```Python```代码的第一行添加如下注释：
```Python
#coding=utf-8

# to do something...
```  
此时整个Python文件会被编码为utf-8  
`physicsLab`也有相关机制在你运行代码的时候自动加上该行注释。

## 优点
1.  ```physicsLab```拥有优秀的与物实存档交互的能力，你甚至可以使用程序完成部分工作之后你再继续完成或者让程序在你已完成的实验的基础上继续完成。  
  如此灵活的功能使得physicsLab即使是在python shell上也能出色的完成工作！
2.  封装了物实里的大量原件，即使是***未解锁的原件***也可以轻易用脚本生成，甚至一些常用的电路也被封装好了！
3.  物理实验室存档的位置有点隐蔽，但用该脚本生成实验时，你无须亲自寻找这个文件在哪里。
4.  绝大多数调用的库皆为Python的内置库，几乎不受第三方依赖的影响。
5.  相比于手动做实验，代码复用率更高，许多逻辑电路已经被封装，只需简单的一行调用即可生成。
6.  程序有利于大型实验的创作
7.  最重要的一点：改存档做出来的实验往往有十分惊艳的效果！

## 不足
1. 对逻辑电路元件的支持是最好的，其余电路的部分原件还没有时间封装。但随着时间的推移，这一问题会逐渐消失。
2. 在物理实验室连接导线只需要点击两下，但用程序连接导线相对麻烦一些。
3. 在物理实验室选择原件只需要点击一下，但用程序选择原件相对麻烦一些。
4. 作者在接下来一段时间内将因为学业难以维护该仓库，但这并不代表弃坑。

## 其他
1. 更多内容请在 [other physicsLab](https://gitee.com/script2000/temporary-warehouse/tree/master/other%20physicsLab) 中查看
2. github: https://github.com/GoodenoughPhysicsLab/physicsLab
3. gitee: https://gitee.com/script2000/physicsLab

## 参与贡献
1.  Fork 本仓库
2.  新建```yourName_xxx```分支
3.  新建`Pull Request(PR)`
4.  完善文档
5.  提`issue`或帮忙回答问题