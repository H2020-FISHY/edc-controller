RULES = [
    """
    (defrule acceptactioncap
        (hspl   (action "is authorized to access")
                (id ?id))
        =>
            (assert (reqcapability (capability "AcceptActionCapability")
                                (hsplid ?id)
                                (detail "")))
            (assert (reqcapability (capability "AppendRuleActionCapability")
                                (hsplid ?id)
                                (detail "FORWARD")))
    )
    """,
    """
    (defrule rejectcap
        (hspl   (action "is not authorized to access")
                (id ?id))
        =>
            (assert (reqcapability (capability "RejectActionCapability")
                                (hsplid ?id)
                                (detail "")))
            (assert (reqcapability (capability "AppendRuleActionCapability")
                                (hsplid ?id)
                                (detail "FORWARD")))
    )
    """,
    """
    (defrule entities-association
        (not (hspl (subject "")))
        (hspl   (id ?id)
                (subject ?sub)
                (action ?act)
                (object ?obj))
        =>
            (entity-analysis ?sub ?obj ?id)
    )
    """,
    """
    (defrule options-analysis
        (option (type "time period")
                (value ?value)
                (hsplid ?hsplid))
        =>
            (assert (reqcapability (capability "MatchActionCapability")
                                (hsplid ?hsplid)
                                (detail "time")
                                ))
            (assert (reqcapability (capability "TimeStartConditionCapability")
                                (hsplid ?hsplid)
                                (detail (get-start-time ?value))
                                ))
            (assert (reqcapability (capability "TimeStopConditionCapability")
                                (hsplid ?hsplid)
                                (detail (get-stop-time ?value))
                                ))
            
    )
    """,
    """
    (defrule path-analysis
        (declare (salience -1))
        (hspl   (id ?id)
                (subject ?sub)
                (action ?act)
                (object ?obj))
        (entity (name ?sub)
                (IP ?ips))
        (entity (name ?obj)
                (IP ?ipd))
        =>
            (find-configuration ?ips ?ipd ?id)
    )
    """,
    """
    (defrule protection-association0
        (hspl   (action "protect confidentiality")
                (id ?id))
        =>
            ;(protection-algorithm-sel confidentiality)
            (assert (reqcapability (capability "EncryptionActionCapability")
                                (hsplid ?id)
                                (detail "")))    
    )
    """,
    """
    (defrule protection-association1
        (hspl   (action "protect integrity")
                (id ?id))
        =>
            ;(protection-algorithm-sel integrity)
            (assert (reqcapability (capability "DataAuthenticationActionCapability")
                    (hsplid ?id)
                    (detail ""))) 
    )
    """,
    """
    (defrule protection-association2
        (hspl   (action "protect confidentiality integrity")
                (id ?id))
        =>
            ;(protection-algorithm-sel confidentiality-integrity)
            (assert (reqcapability (capability "DataAuthenticationActionCapability")
                    (hsplid ?id)
                    (detail "")))
            (assert (reqcapability (capability "EncryptionActionCapability")
                                (hsplid ?id)
                                (detail "")))  
    )
    """,
    """
    (defrule add-ip-cap-src
        (hspl   (id ?id)
                (subject ?sub)
                (action ?act)
                (object ?obj))
        (entity (name ?sub)
                (IP ?ip))
        (not (test(eq ?ip "")))       
         =>
         (assert (reqcapability (capability "IpSourceAddressConditionCapability")
                                (hsplid ?id)
                                (detail ?ip)))
    )
    """,
    """
    (defrule add-ip-cap-dst
        (hspl   (id ?id)
                (subject ?sub)
                (action ?act)
                (object ?obj))
        (entity (name ?obj)
                (IP ?ip))
        (not (test(eq ?ip "")))       
         =>
         (assert (reqcapability (capability "IpDestinationAddressConditionCapability")
                                (hsplid ?id)
                                (detail ?ip)))
    )
    """,
    """
    (defrule entity-req-capabilities
        (hspl   (id ?id)
                (subject ?sub)
                (action ?act)
                (object ?obj))
        =>
            (add-entity-req-capabilities ?id ?sub ?obj)
    )
    """,
]

TEMPLATES = [
    """
    (deftemplate hspl
        (slot id(type STRING))
        (slot subject(type STRING))
        (slot action(type STRING))
        (slot object(type STRING))
    )
    """,
    """
    (deftemplate entity
        (slot name(type STRING))
        (slot IP(type STRING))
        (slot WID(type STRING))
        (slot DID(type STRING))
    )
    """,
    """
    (deftemplate reqcapability
        (slot capability(type STRING))
        (slot detail(type STRING))
        (slot hsplid(type STRING))
    )
    """,
    """
    (deftemplate option
        (slot type(type STRING))
        (slot value(type STRING))
        (slot hsplid(type STRING))
    )
    """,
    """
    (deftemplate configuration
        (slot device(type STRING))
        (slot nsf(type STRING))
        (slot hsplid(type STRING))
    )
    """,
    """
    (deftemplate error
        (slot message(type STRING))
        (slot detail(type STRING))
        (slot hsplid(type STRING))
    )
    """
]
