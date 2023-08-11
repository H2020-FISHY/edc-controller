RULES = [
    """
    (defrule subject-association
        (not (hspl (subject "")))
        (hspl   (id ?id)
                (subject ?sub)
                (action ?act)
                (object ?obj))
        =>
            (subject-analysis ?sub)    
    )
    """,
    """
    (defrule start-path-searching
        (declare (salience -1))
        ?f1 <- (Sources done)
        ?f2 <- (Destinations done)
        =>
            (retract ?f1 ?f2)
            (start-path-search)    
    )
    """,
    """
    (defrule object-association
        (not (hspl (object "")))
        (or (hspl (action "is authorized to access")) 
            (hspl (action "is not authorized to access"))
            (hspl (action "protect confidentiality"))
            (hspl (action "protect integrity"))
            (hspl (action "protect confidentiality integrity"))
        )
        (hspl   (id ?id)
                (subject ?sub)
                (action ?act)
                (object ?obj))
        =>
            (object-filter-protection-analysis ?obj)    
    )
    """,
    """
    (defrule filtering
        (or (hspl (action "is authorized to access")) 
            (hspl (action "is not authorized to access"))
        )  
        =>
            (assert (Case filtering))           
    )
    """,
    """
    (defrule protection
        (or (hspl (action "protect confidentiality")) 
            (hspl (action "protect integrity"))
            (hspl (action "protect confidentiality integrity"))
        )  
        =>
            (assert (Case protection))           
    )
    """,
    """
    (defrule filtering-association0
        (hspl (action "is authorized to access"))  
        =>
            (assert (AcceptActionCapability))           
    )
    """,
    """
    (defrule filtering-association1
        (hspl (action "is not authorized to access"))  
        =>
            (assert (RejectActionCapability))             
    )
    """,
    """
    (defrule protection-association0
        (hspl (action "protect confidentiality"))  
        =>
            (protection-algorithm-sel confidentiality)   
            (assert (IpProtocolTypeConditionCapability esp))   
    )
    """,
    """
    (defrule protection-association1
        (hspl (action "protect integrity"))  
        =>
            (protection-algorithm-sel integrity)      
            (assert (IpProtocolTypeConditionCapability ah))        
    )
    """,
    """
    (defrule protection-association2
        (hspl (action "protect confidentiality integrity"))  
        =>
            (protection-algorithm-sel confidentiality-integrity) 
            (assert (DataAuthenticationActionCapability)) 
            (assert (IpProtocolTypeConditionCapability esp, ah))           
    )
    """,
    """
    (defrule options-analysis
        ?f1 <- (Option time period ?value1 ?value2)  
        =>
            (assert (MatchActionCapability time))
            (assert (TimeStartConditionCapability ?value1))
            (assert (TimeStopConditionCapability ?value2))
            (retract ?f1)
    )
    """,
    """
    (defrule synelixis-use-case-wid
        ?f1 <- (WID: ?wid)
        => 
            (assert (WalletIDConditionCapability ?wid))     
            (retract ?f1)   
    )
    """,
    """
     (defrule synelixis-use-case-did
         ?f1 <- (DID: ?did)
         =>     
             (assert (DistributedIDConditionCapability ?did))  
             (retract ?f1)   
     )
     """,
    """
    (defrule dest-wid-capability-check-deny
        (declare (salience -101))
        (hspl (object ?obj))
        (WalletIDConditionCapability ?wid)
        (RejectActionCapability)
        =>
            (check-destination-device ?obj WalletIDConditionCapability ?wid deny)       
    )
    """,
    """
    (defrule dest-did-capability-check-deny
        (declare (salience -101))
        (hspl (object ?obj))
        (DistributedIDConditionCapability ?did)
        (RejectActionCapability)
        =>
            (check-destination-device ?obj DistributedIDConditionCapability ?did deny)       
    )
    """,
    """
    (defrule dest-wid-capability-check-accept
        (declare (salience -101))
        (hspl (object ?obj))
        (WalletIDConditionCapability ?wid)
        (AcceptActionCapability)
        =>
            (check-destination-device ?obj WalletIDConditionCapability ?wid accept)       
    )
    """,
    """
    (defrule dest-did-capability-check-accept
        (declare (salience -101))
        (hspl (object ?obj))
        (DistributedIDConditionCapability ?did)
        (AcceptActionCapability)
        =>
            (check-destination-device ?obj DistributedIDConditionCapability ?did accept)       
    )
    """,
    """
    (defrule facts-print
        (declare (salience -100))
        (not (Error))
        (not (BlockFinalPrint))
        =>
            (facts-printer)
            (assert (Printed))
    )
    """
]

TEMPLATES = [
    """
    (deftemplate hspl
        (slot id (type STRING))
        (slot subject (type STRING))
        (slot action (type STRING))
        (slot object (type STRING))
    )
    """
]
