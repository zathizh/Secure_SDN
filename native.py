P="_SECURE_SDN_HDR_"
def native(T):
    i=0
    ## matching text with SECURE SDN HEADER
    for l in T:
        if P[i] != l:
            return False
        i = i + 1
    return True
