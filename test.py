class Yeban:
    def __init__(self, name):
        self.name = name
        self.viebal_mamok = 0

    def fuck(self):
        self.viebal_mamok += 1
        return 'ya ebal tvou mati'


danya = Yeban(name='danya')
print(danya.viebal_mamok)
danya.fuck()
print(danya.viebal_mamok)

chel = Yeban(name='da_ya')