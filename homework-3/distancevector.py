from collections import namedtuple

class DistanceVector:
    '''This class encapsulates the distance vector
    '''
    Distance = namedtuple('Distance', ['dest', 'cost', 'next'])

    def __init__(self):
        pass
