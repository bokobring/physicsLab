### 更详细的说明（api及使用方法）

# physicsLab
## 存档读写
你必须指明你要打开的是哪个存档：
```Python
open_Experiment('xxx.sav') # 老版本打开方式，新版本兼容
open_Experiment('blabla') # 在物实保存的本地实验的名字
```
请注意，这个函数只允许调用一次  

如果你想要创建一个实验：
```python
crt_Experiment('存档的名字')
```
请注意，这个函数和打开存档一起**只能调用一次**  

打开的文件是不会读取原实验的状态的，如果你不希望原实验的状态被覆盖，需要调用该函数：  
```Python
read_Experiment()
```

最后你需要调用该函数往存档里写入程序运行之后的结果：  
```Python
write_Experiment()
```

你也可以打开存档查看：
```Python
os_Experiment()
```

你甚至也可以删除实验：
```Python
del_Experiment()
```

## 原件
所有的原件都被写成了一个类（不过我还在施工，无法支持全部原件）  
你可以调用  
```diff
crt_Element(name: str, x : Union[int, float] = 0, y : Union[int, float] = 0, z : Union[int, float] = 0)
```
name可以支持紫兰斋在存档里写的ModelID，也可以支持类的名字  

或者你也可以用类的声明方式：  
```python
Logic_Input() # 创建一个逻辑输入
```
以上2种方法会返回创建出来的原件的self  

以后把所有原件的ModelID与类的名字搬过来  
（如果你着急想看某个原件对应的名字的话，可以直接在源码中看，注释写得很详细了）  
  
我们创建的原件可以轻易地知道其坐标，却很难知道他的self，我们可以使用这个函数：
```python
get_Element(x, y, z)
```
返回值是这个坐标对应原件的self，若不存在抛出RuntimeError  

我们也可以删除原件：
```python
del_Element(self) -> None
```
因为传入参数为self，所以必要时也需要用get_Element。

## 导线
连接导线提供了2种方式  
第一种：  
```diff
crt_wire(SourcePin, TargetPin, color: str = '蓝') -> None
```
所有原件都定义得有自己的引脚名称，这里举个例子：  
```diff
a = Or_Gate(0.1, 0.1, 0)
crt_wire(a.o, a.i_up)
```
引脚的命名规范：（适用于逻电）  
1个输入引脚：i  
2个输入引脚：i_up, i_low  
3个输入引脚：i_up, i_mid, i_low  
4个输入引脚：i_up, i_upmid, i_lowmid, i_low  
输出是一样的，仅仅换成了o_xxx罢了。  
模电的命名可能是根据左右引脚来区分的，也就是l_up, r_low之类的，也可能是根据物实的引脚名  

另一种连接引脚的方式是不推荐使用的老函数：  
```diff
old_crt_wire(SourceLabel, SourcePin : int, TargetLabel, TargetPin : int, color = "蓝") -> None
```
连接导线的方式是更偏于物实存档的原始方案，即用数字来表示某个引脚  
下面呈现部分原件引脚图（第一种其实就是对这个老函数更方便的封装）：  
（显示有问题，建议打开“编辑”浏览）
D触发器：          
2    0                  
                             
3    1                          

是门、非门： 
0 1 

比较器:
1
    2
0  

逻辑输入、逻辑输出：
0  

三引脚门电路：   
0             
    2         
1             

全加器：  
2    0  
3  
4    1  

继电器pin  
0   4  
  1    
2   3  
  
二位乘法器：  
4  0  
5  1  
6  2  
7  3  
很明显比第一种更麻烦  
  
除了创建导线外，也可以删除导线：  
```diff
del_wire(element.o, element2.i)
```
使用方法与crt_wire一模一样  
  
（这篇readme应该介绍了大部分常用功能）

# 物实程序化3  
我也曾试过物实程序化3，发现爆了文件错误  
与原作者（xuzhegnx）沟通之后了解到：xuzhengx直接把冰如冷的教程拿来索引原件  
这是个大坑，对感兴趣的同学应该有帮助