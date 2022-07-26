from zksk import Secret, DLRep
from zksk import utils
from petlib.ec import EcGroup
from petlib.bn import Bn

def ZK_equality(G,H):

    #Generate two El-Gamal ciphertexts (C1,C2) and (D1,D2)
    
    # Setup: Peggy and Victor agree on two group generators.

    # taken arguments as G,H = utils.make_generators(num=2, seed=12387)

    # Setup: generate a secret randomizer.

    # r1 = Secret(utils.get_random_num(bits=128))
    # r2 = Secret(utils.get_random_num(bits=128))

    group = EcGroup()
    r1 = Secret(group.order().random())
    r2 = Secret(group.order().random())

    # Setup: define a randomizer with an unknown value.
    m = Secret(Bn(42)) #Verifier calls the secret m instead of r

    C1 = r1.value*G
    C2 = r1.value*H+m.value*G
    D1 = r2.value*G
    D2 = r2.value*H+m.value*G

    #Generate a NIZK proving equality of the plaintexts
    stmt = DLRep(C1,r1*G) & DLRep(C2,r1*H+m*G) & DLRep(D1,r2*G) & DLRep(D2,r2*H+m*G)

    zk_proof = stmt.prove()

    #Return two ciphertexts and the proof
    return (C1,C2), (D1,D2), zk_proof
