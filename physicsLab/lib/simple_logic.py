# -*- coding: utf-8 -*-
import physicsLab.errors as errors
import physicsLab.circuit.elementXYZ as _elementXYZ

from .wires import unitPin, crt_Wires
from physicsLab._tools import roundData
from physicsLab.circuit import elements
from physicsLab.experiment import get_Experiment
from physicsLab.enums import ExperimentType
from physicsLab.typehint import numType, Optional, Self

class Const_NoGate:
    ''' 只读非门，若没有则创建一个只读非门，若已存在则不会创建新的元件 '''
    __singleton: Optional["Const_NoGate"]  = None
    __singleton_NoGate = None

    def __new__(cls,
                x: numType = 0,
                y: numType = 0,
                z: numType = 0,
                elementXYZ: Optional[bool] = None
    ) -> Self:
        if Const_NoGate.__singleton_NoGate is None:
            Const_NoGate.__singleton = object.__new__(cls)
            Const_NoGate.__singleton_NoGate = elements.No_Gate(x, y, z, elementXYZ)

        assert Const_NoGate.__singleton is not None
        return Const_NoGate.__singleton

    @property
    def o(self):
        assert Const_NoGate.__singleton_NoGate is not None
        return Const_NoGate.__singleton_NoGate.o

class Super_AndGate:
    ''' 多引脚与门, 引脚数为num '''
    def __init__(self, x: numType = 0, y: numType = 0, z: numType = 0, elementXYZ: bool = False, num: int = 4) -> None:
        if not isinstance(x, (int, float)) or not isinstance(y, (int, float)) or \
           not isinstance(z, (int, float)) or not isinstance(elementXYZ, bool) or \
           not isinstance(num, int) or num <= 1:
            raise TypeError

        if not (elementXYZ is True or (_elementXYZ.is_elementXYZ() is True and elementXYZ is None)):
            x, y, z = _elementXYZ.translateXYZ(x, y, z)
        x, y, z = roundData(x, y, z)

        if num == 2:
            m = elements.And_Gate(x, y, z, elementXYZ=True)
            self._inputs = [m.i_low, m.i_up]
            self._outputs = unitPin(self, m.o)
            return
        elif num == 3 or num == 4:
            m = elements.Multiplier(x, y, z, elementXYZ=True)
            self._inputs = [m.i_low, m.i_lowmid, m.i_upmid, m.i_up]
            self._outputs = unitPin(self, m.o_up)
            if num == 3:
                m.i_up - m.i_upmid
            return
        if num == 5:
            m = elements.Multiplier(x, y, z, elementXYZ=True)
            a = elements.And_Gate(x, y, z, elementXYZ=True)
            m.o_up - a.i_low
            self._inputs = [m.i_low, m.i_lowmid, m.i_upmid, m.i_up, a.i_up]
            self._outputs = unitPin(self, a.o)
            return

        muls, mod_num = divmod(num, 4)
        self._inputs = []

        if mod_num == 2 or mod_num == 3:
            muls = [elements.Multiplier(x, y, z, elementXYZ=True) for _ in range(muls)]
            tmp = Super_AndGate(x, y, z, True, len(muls) + 1)
        elif mod_num == 1:
            muls = [elements.Multiplier(x, y, z, elementXYZ=True) for _ in range(muls - 1)]
            tmp = Super_AndGate(x, y, z, True, len(muls) + 5)
        else: # end_num == 0
            muls = [elements.Multiplier(x, y, z, elementXYZ=True) for _ in range(muls)]
            tmp = Super_AndGate(x, y, z, True, len(muls))

        if mod_num == 3:
            end_element = elements.Multiplier(x, y, z, elementXYZ=True)
            end_element.i_up - end_element.i_upmid
            crt_Wires(unitPin(None, *(mul.o_up for mul in muls), end_element.o_up), tmp.inputs)
            for mul in muls:
                self._inputs += [mul.i_low, mul.i_lowmid, mul.i_upmid, mul.i_up]
            self._inputs += [end_element.i_low, end_element.i_lowmid, end_element.i_upmid, end_element.i_up]

        elif mod_num == 2:
            end_element = elements.And_Gate(x, y, z, elementXYZ=True)
            crt_Wires(unitPin(None, *(mul.o_up for mul in muls), end_element.o), tmp.inputs)
            for mul in muls:
                self._inputs += [mul.i_low, mul.i_lowmid, mul.i_upmid, mul.i_up]
            self._inputs += [end_element.i_low, end_element.i_up]

        elif mod_num == 1:
            for mul, i in zip(muls, tmp._inputs):
                mul.o_up - i
            for mul in muls:
                self._inputs += [mul.i_low, mul.i_lowmid, mul.i_upmid, mul.i_up]
            self._inputs += tmp._inputs[len(muls):]

        else: # end_num == 0
            crt_Wires(unitPin(None, *(mul.o_up for mul in muls)), tmp.inputs)
            for mul in muls:
                self._inputs += [mul.i_low, mul.i_lowmid, mul.i_upmid, mul.i_up]

        self._outputs = tmp.output

    @property
    def inputs(self) -> unitPin:
        return unitPin(
            self,
            *self._inputs
        )

    @property
    def output(self) -> unitPin:
        return self._outputs

class Tick_Counter:
    ''' 当 逻辑输入 输入了num次, 就输出为1, 否则为0
        如果输出为1, 则进入下一个周期，在下一次输入了num次时输出为1, 否则为0
    '''
    def __init__(self, x: numType = 0, y: numType = 0, z: numType = 0, elementXYZ: bool = False, num: int = 2) -> None:
        if not isinstance(x, (int, float)) or not isinstance(y, (int, float)) or \
           not isinstance(z, (int, float)) or not isinstance(elementXYZ, bool) or \
           not isinstance(num, int) or num <= 1:
            raise TypeError

        if not (elementXYZ is True or (_elementXYZ.is_elementXYZ() is True and elementXYZ is None)):
            x, y, z = _elementXYZ.translateXYZ(x, y, z)
        x, y, z = roundData(x, y, z)

        if num == 2:
            self._output = elements.T_Flipflop(x, y, z, True)
        else:
            if num >= 16:
                raise Exception("Do not support num >= 16 in this version")

            self._output = elements.Counter(x + 1, y, z, True)

            bitlist = []
            num -= 1
            for _ in range(4):
                bitlist.append(num & 1)
                num >>= 1

            output_pins = []
            for i, a_bit in enumerate(bitlist):
                if a_bit:
                    _p = [self._output.o_low, self._output.o_lowmid, self._output.o_upmid, self._output.o_up][i]
                    output_pins.append(_p)
                    self._o = unitPin(self, _p)

            if len(output_pins) >= 2:
                sa = Super_AndGate(x + 1, y, z, True, len(output_pins))
                self._o = sa.output
                crt_Wires(unitPin(None, *output_pins), sa.inputs)

            imp = elements.Imp_Gate(x, y + 1, z, True)
            or_gate = elements.Or_Gate(x, y, z, True)
            or_gate.i_low - or_gate.o
            or_gate.o - imp.i_up
            or_gate.i_up - self._output.i_up
            imp.o - self._output.i_low
            crt_Wires(self._o, imp.i_low)

    @property
    def input(self) -> unitPin:
        if isinstance(self._output, elements.T_Flipflop):
            return unitPin(self, self._output.i_low)
        else: # isinstance(self._output, elements.Counter)
            return unitPin(self, self._output.i_up)

    @property
    def output(self) -> unitPin:
        if isinstance(self._output, elements.T_Flipflop):
            return unitPin(self, self._output.o_low)
        else: # isinstance(self._output, elements.Counter)
            return self._o

class Two_four_Decoder:
    ''' 2-4译码器 '''
    def __init__(self, x: numType = 0, y: numType = 0, z: numType = 0, elementXYZ: bool = False) -> None:
        # 元件坐标系，如果输入坐标不是元件坐标系就强转为元件坐标系
        if not (elementXYZ is True or (_elementXYZ.is_elementXYZ() is True and elementXYZ is None)):
            x, y, z = _elementXYZ.translateXYZ(x, y, z)
        x, y, z = roundData(x, y, z)

        self.nor_gate = elements.Nor_Gate(x, y, z, True)
        self.nimp_gate1 = elements.Nimp_Gate(x + 1, y, z, True)
        self.nimp_gate2 = elements.Nimp_Gate(x + 1, y + 1, z, True)
        self.and_gate = elements.And_Gate(x, y + 1, z, True)
        self.nor_gate.i_up - self.nimp_gate1.i_low
        self.nimp_gate1.i_low - self.nimp_gate2.i_up
        self.nimp_gate2.i_up - self.and_gate.i_up
        self.nor_gate.i_low - self.nimp_gate1.i_up
        self.nimp_gate1.i_up - self.nimp_gate2.i_low
        self.nimp_gate2.i_low - self.and_gate.i_low

    @property
    def inputs(self) -> unitPin:
        return unitPin(
            self,
            self.nor_gate.i_low,
            self.and_gate.i_up,
        )

    @property
    def outputs(self) -> unitPin:
        return unitPin(
            self,
            self.nor_gate.o,
            self.nimp_gate1.o,
            self.nimp_gate2.o,
            self.and_gate.o,
        )

class _Simple_Logic_Meta(type):
    def __call__(cls,
                 x: numType = 0,
                 y: numType = 0,
                 z: numType = 0,
                 elementXYZ: Optional[bool] = None,  # x, y, z是否为元件坐标系
                 bitLength: int = 4,
                 heading: bool = False,  # False: 生成的元件为竖直方向，否则为横方向
                 fold: bool = False,  # False: 生成元件时不会在同一水平面的元件超过一定数量后z + 1继续生成元件
                 foldMaxNum: int = 4,  # 达到foldMaxNum个元件数时即在z轴自动折叠
                 *args, **kwags
    ):
        self = cls.__new__(cls)
        if get_Experiment().experiment_type != ExperimentType.Circuit:
            raise errors.ExperimentTypeError

        if foldMaxNum <= 0 or not(
            isinstance(x, (int, float)) or
            isinstance(y, (int, float)) or
            isinstance(z, (int, float)) or
            isinstance(elementXYZ, bool) or
            isinstance(heading, bool) or
            isinstance(fold, bool) or
            isinstance(foldMaxNum, int)
        ):
            raise TypeError
        if not isinstance(bitLength, int) or bitLength < 1:
            raise errors.bitLengthError("bitLength must get a integer")

        # 元件坐标系，如果输入坐标不是元件坐标系就强转为元件坐标系
        if not (elementXYZ is True or (_elementXYZ.is_elementXYZ() is True and elementXYZ is None)):
            x, y, z = _elementXYZ.translateXYZ(x, y, z)
        x, y, z = roundData(x, y, z) # type: ignore -> result type: tuple

        self.__init__(x=x,
                      y=y,
                      z=z,
                      elementXYZ=elementXYZ,
                      bitLength=bitLength,
                      heading=heading,
                      fold=fold,
                      foldMaxNum=foldMaxNum,
                      *args, **kwags)
        assert hasattr(self, "_elements")

        return self

class _Base(metaclass=_Simple_Logic_Meta):
    def __getitem__(self, item: int) -> "elements.CircuitBase":
        if not isinstance(item, int):
            raise TypeError

        return self._elements[item]

    def set_HighLevelValue(self, num: numType) -> Self:
        ''' 设置高电平的值 '''
        for element in self._elements:
            element.set_HighLeaveValue(num)
        return self

    def set_LowLevelValue(self, num: numType) -> Self:
        ''' 设置低电平的值 '''
        for element in self._elements:
            element.set_LowLeaveValue(num)
        return self

class Sum(_Base):
    ''' 模块化加法电路 '''
    def __init__(self,
                 x: numType = 0,
                 y: numType = 0,
                 z: numType = 0,
                 elementXYZ: Optional[bool] = None,  # x, y, z是否为元件坐标系
                 bitLength: int = 4,
                 heading: bool = False,  # False: 生成的元件为竖直方向，否则为横方向
                 fold: bool = False,  # False: 生成元件时不会在同一水平面的元件超过一定数量后z + 1继续生成元件
                 foldMaxNum: int = 4  # 达到foldMaxNum个元件数时即在z轴自动折叠
                 ) -> None:
        self._elements: list = []

        if heading:
            if fold:
                zcor = z
                for i in range(bitLength):
                    self._elements.append(elements.Full_Adder(x + i % foldMaxNum, y, zcor, True))
                    if i == foldMaxNum - 1:
                        zcor += 1
            else:
                for increase in range(bitLength):
                    self._elements.append(elements.Full_Adder(x + increase, y, z, True))
        else:
            if fold:
                zcor = z
                for i in range(bitLength):
                    self._elements.append(
                        elements.Full_Adder(x, y + (i % foldMaxNum) * 2, zcor, True)
                    )
                    if i == foldMaxNum - 1:
                        zcor += 1
            else:
                for increase in range(bitLength):
                    self._elements.append(elements.Full_Adder(x, y + increase * 2, z, True))

        # 连接导线
        for i in range(self._elements.__len__() - 1):
                self._elements[i].o_low - self._elements[i + 1].i_low

    @property
    def input1(self) -> unitPin:
        ''' 加数1 '''
        return unitPin(
            self,
            *(element.i_mid for element in self._elements)
        )

    @property
    def input2(self) -> unitPin:
        ''' 加数2 '''
        return unitPin(
            self,
            *(element.i_up for element in self._elements)
        )

    @property
    def outputs(self) -> unitPin:
        ''' 加法的结果 '''
        return unitPin(
            self,
            *(element.o_up for element in self._elements),
            self._elements[-1].o_low
        )

class Sub(_Base):
    ''' 模块化减法电路 '''
    def __init__(self,
                 x: numType = 0,
                 y: numType = 0,
                 z: numType = 0,
                 elementXYZ: Optional[bool] = None,  # x, y, z是否为元件坐标系
                 bitLength: int = 4, # 减法器的最大计算比特数
                 heading: bool = False,  # False: 生成的元件为竖直方向，否则为横方向
                 fold: bool = False,  # False: 生成元件时不会在同一水平面的元件超过一定数量后z + 1继续生成元件
                 foldMaxNum: int = 4  # 达到foldMaxNum个元件数时即在z轴自动折叠
                 ) -> None:
        self._elements: list = [Const_NoGate(x, y, z, True)]
        self._noGates: list = []
        self._fullAdders: list = []

        if heading:
            if fold:
                zcor = z
                for i in range(bitLength):
                    self._fullAdders.append(
                        elements.Full_Adder(x + i % foldMaxNum, y - 2, zcor, True)
                    )
                    self._noGates.append(
                        elements.No_Gate(x + i % foldMaxNum, y, zcor, True)
                    )
                    if i == foldMaxNum - 1:
                        zcor += 1
            else:
                for increase in range(bitLength):
                    self._fullAdders.append(
                        elements.Full_Adder(x + increase, y - 2, z, True)
                    )
                    self._noGates.append(
                        elements.No_Gate(x + increase, y, z, True)
                    )
        else:
            if fold:
                zcor = z
                for i in range(bitLength):
                    self._fullAdders.append(
                        elements.Full_Adder(x + 1, y + (i % foldMaxNum) * 2, zcor, True)
                    )
                    self._noGates.append(
                        elements.No_Gate(x, y + (i % foldMaxNum) * 2 + 1, zcor, True)
                    )
                    if i == foldMaxNum - 1:
                        zcor += 1
            else:
                for increase in range(bitLength):
                    self._fullAdders.append(
                        elements.Full_Adder(x + 1, y + increase * 2, z, True)
                    )
                    self._noGates.append(
                        elements.No_Gate(x, y + increase * 2 + 1, z, True)
                    )

        # 连接导线
        self._elements[0].o - self._fullAdders[0].i_low
        for i in range(self._fullAdders.__len__() - 1):
            self._fullAdders[i].o_low - self._fullAdders[i + 1].i_low
            self._noGates[i].o - self._fullAdders[i].i_mid
        self._noGates[-1].o - self._fullAdders[-1].i_mid

        self._elements.extend(self._fullAdders + self._noGates)

    @property
    def minuend(self) -> unitPin:
        ''' 被减数 '''
        return unitPin(
            self,
            *(e.i_up for e in self._fullAdders)
        )

    # 减数
    @property
    def subtrahend(self):
        ''' 减数 '''
        return unitPin(
            self,
            *(e.i for e in self._noGates)
        )

    @property
    def outputs(self):
        ''' 减法的结果 '''
        return unitPin(
            self,
            *(e.o_up for e in self._fullAdders),
            self._fullAdders[-1].o_low
        )

class D_WaterLamp(_Base):
    ''' D触发器流水灯 '''
    def __init__(self,
                 x: numType = 0,
                 y: numType = 0,
                 z: numType = 0,
                 elementXYZ: Optional[bool] = None, # x, y, z是否为元件坐标系
                 bitLength: int = 4,
                 heading: bool = False, # False: 生成的元件为竖直方向，否则为横方向
                 fold: bool = False, # False: 生成元件时不会在同一水平面的元件超过一定数量后z + 1继续生成元件
                 foldMaxNum: int = 4, # 达到foldMaxNum个元件数时即在z轴自动折叠
                 is_loop: bool = True # 是否使流水灯循环
                 ) -> None:
        if bitLength < 2:
            raise errors.bitLengthError

        if not isinstance(is_loop, bool):
            raise TypeError

        self.is_bitlen_equal_to_2: bool = False
        if bitLength == 2:
            self.is_bitlen_equal_to_2 = True
            self._elements = [elements.T_Flipflop(x, y, z, True)]
            return

        self._elements: list = []

        if heading:
            if fold:
                zcor = z
                for i in range(bitLength):
                    self._elements.append(
                        elements.D_Flipflop(x + i % foldMaxNum, y, zcor, True)
                    )
                    if i == foldMaxNum - 1:
                        zcor += 1
            else:
                for increase in range(bitLength):
                    self._elements.append(
                        elements.D_Flipflop(x + increase, y, z, True)
                    )
        else:
            if fold:
                zcor = z
                for i in range(bitLength):
                    self._elements.append(
                        elements.D_Flipflop(x, y + (i % foldMaxNum) * 2, zcor, True)
                    )
                    if i == foldMaxNum - 1:
                        zcor += 1
            else:
                for increase in range(bitLength):
                    self._elements.append(
                        elements.D_Flipflop(x, y + increase * 2, z, True)
                    )

        # 连接clk
        for i in range(len(self._elements) - 1):
            self._elements[i].i_low - self._elements[i + 1].i_low
        # 连接数据传输导线
        self._elements[0].o_low - self._elements[1].i_up
        for i in range(1, len(self._elements) - 1):
            self._elements[i].o_up - self._elements[i + 1].i_up
        # 流水灯循环导线
        if is_loop:
            self._elements[-1].o_low - self._elements[0].i_up
        else:
            firstElement = self._elements[0]
            orGate = elements.Or_Gate(*firstElement.get_Position(), True)
            orGate.i_up - orGate.o
            orGate.o - firstElement.i_up
            orGate.i_low - firstElement.i_low

    @property
    def inputs(self) -> unitPin:
        return unitPin(
            self,
            self._elements[0].i_low
        )

    @property
    def outputs(self) -> unitPin:
        if not self.is_bitlen_equal_to_2:
            return unitPin(
                self,
                self._elements[0].o_low,
                *(element.o_up for element in self._elements[1:])
            )
        else:
            return unitPin(
                self,
                self._elements[0].o_up,
                self._elements[0].o_low
            )

    # 与data_Output相反的引脚
    @property
    def neg_outputs(self) -> unitPin:
        return unitPin(
            self,
            self._elements[0].o_up,
            *(element.o_low for element in self._elements[1:])
        )

class Inputs(_Base):
    '''  多个逻辑输入 '''
    def __init__(self,
                 x: numType = 0,
                 y: numType = 0,
                 z: numType = 0,
                 elementXYZ: Optional[bool] = None,  # x, y, z是否为元件坐标系
                 bitLength: int = 4,
                 heading: bool = False,  # False: 生成的元件为竖直方向，否则为横方向
                 fold: bool = False,  # False: 生成元件时不会在同一水平面的元件超过一定数量后z + 1继续生成元件
                 foldMaxNum: int = 8  # 达到foldMaxNum个元件数时即在z轴自动折叠
                 ) -> None:
        self._elements: list = []
        if heading:
            if fold:
                zcor = z
                for i in range(bitLength):
                    self._elements.append(
                        elements.Logic_Input(x + i % foldMaxNum, y, zcor, True)
                    )
                    if i == foldMaxNum - 1:
                        zcor += 1
            else:
                for i in range(bitLength):
                    self._elements.append(
                        elements.Logic_Input(x + i, y, z, True)
                    )
        else:
            if fold:
                zcor = z
                for i in range(bitLength):
                    self._elements.append(
                        elements.Logic_Input(x, y + i % foldMaxNum, zcor, True)
                    )
                    if i == foldMaxNum - 1:
                        zcor += 1
            else:
                for i in range(bitLength):
                    self._elements.append(
                        elements.Logic_Input(x, y + i, z, True)
                    )

    @property
    def outputs(self) -> unitPin:
        return unitPin(
            self,
            *(element.o for element in self._elements)
        )

class Outputs(_Base):
    '''  多个逻辑输入 '''
    def __init__(self,
                 x: numType = 0,
                 y: numType = 0,
                 z: numType = 0,
                 elementXYZ: Optional[bool] = None,  # x, y, z是否为元件坐标系
                 bitLength: int = 4,
                 heading: bool = False,  # False: 生成的元件为竖直方向，否则为横方向
                 fold: bool = False,  # False: 生成元件时不会在同一水平面的元件超过一定数量后z + 1继续生成元件
                 foldMaxNum: int = 8  # 达到foldMaxNum个元件数时即在z轴自动折叠
                 ) -> None:
        self._elements: list = []
        if heading:
            if fold:
                zcor = z
                for i in range(bitLength):
                    self._elements.append(
                        elements.Logic_Output(x + i % foldMaxNum, y, zcor, True)
                    )
                    if i == foldMaxNum - 1:
                        zcor += 1
            else:
                for i in range(bitLength):
                    self._elements.append(
                        elements.Logic_Output(x + i, y, z, True)
                    )
        else:
            if fold:
                zcor = z
                for i in range(bitLength):
                    self._elements.append(
                        elements.Logic_Output(x, y + i % foldMaxNum, zcor, True)
                    )
                    if i == foldMaxNum - 1:
                        zcor += 1
            else:
                for i in range(bitLength):
                    self._elements.append(
                        elements.Logic_Output(x, y + i, z, True)
                    )

    @property
    def inputs(self) -> unitPin:
        return unitPin(
            self,
            *(element.i for element in self._elements)
        )