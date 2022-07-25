from zksk import Secret, DLRep
from zksk import utils

def ZK_equality(G,H):

    #Generate two El-Gamal ciphertexts (C1,C2) and (D1,D2)
    
    # Setup: Peggy and Victor agree on two group generators.
    # taken arguments G, H = utils.make_generators(num=2, seed=42)
    # Setup: generate a secret randomizer.

    r1 = Secret(utils.get_random_num(bits=128))
    r2 = Secret(utils.get_random_num(bits=128))

    # Setup: define a randomizer with an unknown value.
    m = Secret() #Verifier calls the secret m instead of r

    C1 = r1*G
    C2 = r1*H+m*G
    D1 = r2*G
    D2 = r2*H+m*G

    #Generate a NIZK proving equality of the plaintexts
    stmt = DLRep(C1,r1*G) & DLRep(C2,r1*H+m*G) & DLRep(D1,r2*G) & DLRep(D2,r2*H+m*G)

    zk_proof = stmt.proof()

    #Return two ciphertexts and the proof
    return (C1,C2), (D1,D2), zk_proof

