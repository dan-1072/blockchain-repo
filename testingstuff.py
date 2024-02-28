class Engine:

    def __init__(self):
        self.var1 = 0

class Car:

    def __init__(self):
        self._engine = Engine()
    
    def set_engine(self):
        self._engine.var1 = 1

    def check_engine(self):
        print(self._engine)

lst = []
fiat_500 = Car()
lst.append(fiat_500._engine)

def set_external(car):
    car.set_engine()

set_external(fiat_500)

fiat_500.check_engine()
print(lst)
print(lst[0].var1)

