##! Script for discovering United States Social Security Numbers being sent in clear
##! text in HTTP and SMTP traffic.

# Hawaii 575-576 & 750-751
# Colorado 521-524 & 650-653
# New Mexico 525 & 585 & 648-649
# Arizona 526-527 & 600-601 & 764-765
# Texas 449-467 & 627-647
# California 545-573 & 602-626
# Utah 528-529
# Idaho 518-519
# Nevada 530 & 680
# Wyoming 520
# Washington 531-539
# Oregon 540-544
# New Hampshire 001-003
# Maine 004-007
# Vermont 008-009
# Massachusetts 010-034
# Rhode Island 035-039
# Connecticut 040-049
# New York 050-134
# New Jersey 135-158
# Pennsylvania 159-211
# Maryland 212-220
# Delaware 221-222
# Virginia 223-231 & 691-699
# West Virginia 233-236
# North Carolina 237-246 & 681-690
# South Carolina 247-251 & 654-658
# Georgia 252-260 & 667-675
# Florida 261-267 & 589-595 & 765-772
# Ohio 268-302
# Indiana 303-317
# Illinois 318-361
# Michigan 362-386
# Wisconsin 387-399
# Kentucky 400-407
# Tennessee 408-415 & 756-763
# Alabama 416-424
# Mississippi425-428 & 587-588 & 752-755
# Arkansas 429-432 & 676-679
# Louisiana 433-439 & 659-665    
# Oklahoma 440-448   
# Minnesota 468-477  
# Iowa 478-485 
# Missouri 486-500   
# North Dakota 501-502   
# South Dakota 503-504   
# Nebraska 505-508   
# Kansas 508-515 
# Montana 516-517    
# Alaska 574 
# District of Columbia 577-579   
# Virgin Islands 580 
# Guam, American Samoa & Philippines 586 
# Puerto Rico 596-599    

# TODO: We might consider using the Input framework (Input::add_table)
# to keep this updated when Input framework is supported on Corelight
# in a future release
redef SsnExposure::prefixes += {
    [$state="Utah", $low=528, $high=529],
    [$state="Idaho", $low=518, $high=519],
    [$state="CaliforniaA", $low=545, $high=573],
    [$state="CaliforniaB", $low=602, $high=626],
    [$state="ArizonaA", $low=526, $high=527],
    [$state="ArizonaB", $low=600, $high=601],
    [$state="ArizonaC", $low=764, $high=765],
    [$state="TexasA", $low=449, $high=467],
    [$state="TexasB", $low=627, $high=647],
    [$state="HawaiiA", $low=575, $high=576],
    [$state="HawaiiB", $low=750, $high=751],
    [$state="ColoradoA", $low=521, $high=524],
    [$state="ColoradoB", $low=650, $high=653],
    [$state="NewMexicoA", $low=525, $high=525],
    [$state="NewMexicoB", $low=585, $high=585],
    [$state="NewMexicoC", $low=648, $high=649],
    [$state="NevadaA", $low=530, $high=530],
    [$state="NevadaB", $low=680, $high=680],
    [$state="Wyoming", $low=520, $high=520],
    [$state="Washington", $low=531, $high=539],
    [$state="Oregon", $low=540, $high=544],
    [$state="NewHampshire", $low=001, $high=003],
    [$state="Maine", $low=004, $high=007],
    [$state="Vermont", $low=008, $high=009],
    [$state="Massachusetts", $low=010, $high=034],
    [$state="RhodeIsland", $low=035, $high=039],
    [$state="Connecticut", $low=040, $high=049],
    [$state="NewYork", $low=050, $high=134],
    [$state="NewJersey", $low=135, $high=158],
    [$state="Pennsylvania", $low=159, $high=211],
    [$state="Maryland", $low=212, $high=220],
    [$state="Delaware", $low=221, $high=222],
    [$state="VirginiaA", $low=223, $high=231],
    [$state="VirginiaB", $low=691, $high=699],
    [$state="WestVirginia", $low=233, $high=236],
    [$state="NorthCarolinaA", $low=237, $high=246],
    [$state="NorthCarolinaB", $low=681, $high=690],
    [$state="SouthCarolinaA", $low=247, $high=251],
    [$state="SouthCarolinaB", $low=654, $high=658],
    [$state="GeorgiaA", $low=252, $high=260],
    [$state="GeorgiaB", $low=667, $high=675],
    [$state="FloridaA", $low=261, $high=267],
    [$state="FloridaB", $low=589, $high=595],
    [$state="FloridaC", $low=765, $high=772],
    [$state="Ohio", $low=268, $high=302],
    [$state="Indiana", $low=303, $high=317],
    [$state="Illinois", $low=318, $high=361],
    [$state="Michigan", $low=362, $high=386],
    [$state="Wisconsin", $low=387, $high=399],
    [$state="Kentucky", $low=400, $high=407],
    [$state="TennesseeA", $low=408, $high=415],
    [$state="TennesseeB", $low=756, $high=763],
    [$state="Alabama", $low=416, $high=424],
    [$state="MississippiA", $low=425, $high=428],
    [$state="MississippiB", $low=587, $high=588],
    [$state="MississippiC", $low=752, $high=755],
    [$state="ArkansasA", $low=429, $high=432],
    [$state="ArkansesB", $low=676, $high=679],
    [$state="LouisianaA", $low=433, $high=439],
    [$state="LouisianaB", $low=659, $high=665],
    [$state="Oklahoma", $low=440, $high=448],
    [$state="Minnesota", $low=468, $high=477],
    [$state="Iowa", $low=478, $high=485],
    [$state="Missouri", $low=486, $high=500],
    [$state="NorthDakota", $low=501, $high=502],
    [$state="SouthDakota", $low=503, $high=504],
    [$state="Nebraska", $low=505, $high=508],
    [$state="Kansas", $low=508, $high=515],
    [$state="Montana", $low=516, $high=517],
    [$state="Alaska", $low=574, $high=574],
    [$state="WashingtonDC", $low=577, $high=579],
    [$state="VirginIslands", $low=580, $high=580],
    [$state="Guam", $low=586, $high=586],
    [$state="PuertoRico", $low=596, $high=599],
};

redef SsnExposure::redact_log = T;
redef SsnExposure::redaction_char = "#";
redef SsnExposure::redaction_summary_length = 4096;

# Hook the Notice framework policy and make changes to some alerts
#hook Notice::policy(n: Notice::Info)
#{
#    if ( n$note == SsnExposure::Found )
#    {
#        delete n$actions[Notice::ACTION_LOG];
#        # add n$actions[Notice::ACTION_ALARM];
#    }
#}

