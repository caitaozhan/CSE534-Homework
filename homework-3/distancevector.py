from collections import namedtuple

class DistanceVector:
    '''This class encapsulates the distance vector
    '''
    Distance = namedtuple('Distance', ['Dest', 'Cost', 'Next'])

    def __init__(self, hostname):
        '''
            Read neighbor file and init the distance vector
        '''
        self.__dv = []  # a distance vector is essentially a list
        try:
            with open('/home/neighbor/' + hostname, 'r') as f:
                lines = f.readlines()
                for line in lines:
                    line = line.strip().split(' ')
                    neighbor = line[0]
                    weight   = line[1]
                    self.__dv.append(self.Distance(Dest=neighbor, Cost=int(weight), Next=neighbor))
        except Exception as e:
            print(e)

    def add_distance(self, distance):
        self.__dv.append(distance)


    dv = property()

    @dv.getter
    def dv(self):
        return self.__dv


    def __str__(self):
        string = ''
        for distance in self.__dv:
            string += str(distance) + '\n'
        return string


if __name__ == '__main__':
    dv = DistanceVector('r1')
    print(dv)
