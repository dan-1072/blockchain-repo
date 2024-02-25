class Car:

    def __init__(self):
        self._engine = 0
    
    def set_engine(self):
        self._engine = 1

    def check_engine(self):
        print(self.engine)

fiat_500 = Car()

def set_external(car):
    car.set_engine()

set_external(fiat_500)

fiat_500.check_engine()