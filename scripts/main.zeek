##! Script for discovering United States Social Security Numbers being sent in clear
##! text in HTTP and SMTP traffic.

@load base/frameworks/notice

module SsnExposure;

export {
	## SSN exposure log ID definition.
	redef enum Log::ID += { LOG };

	redef enum Notice::Type += { 
		Found
	};

	type Info: record {
		## When the SSN was seen.
		ts:   time    &log;
		## Unique ID for the connection.
		uid:  string  &log;
		## Connection details.
		id:   conn_id &log;
		## SSN that was discovered.
		ssn:  string  &log &optional;
		## Data that was received when the SSN was discovered.
		data: string  &log;
	};

	type StateRange: record {
		## The name of the state this range represents.
		state: string &optional;
		## Value representing the beginning of the state range.
		low: count;
		## Value representing the end of the state range.
		high: count;
	};
	
	## A file meant for the input framework to read in.  It only needs
	## to contain a list of SSNs and the SSNs should be put
	## in without any separators (e.g. 123456789).
	const ssn_file = "" &redef;

	## This is an alternate to acquiring a list of known SSNs held
	## at your business/university.  This will certainly be the quickest
	## path to results in most cases and seems to work fairly well.
	##
	## ..note: Check the following URL and set this value to what you expect 
	##         most SSNs at your site to be: http://www.mrfa.org/ssn.htm
	##         
	##         For example, a state university can probably assume that many 
	##         SSNs they hold will be for people from that state or possibly
	##         neighboring states.
	const prefixes: set[StateRange] = {} &redef;

	## If you want to avoid creating new PII logs with Bro, you can redact the 
	## ssn_exposure log with this option.  Notices are automatically and
	## unchangeably redacted.
	const redact_log = F &redef;

	## Regular expression that matches US Social Security Numbers loosely.
	## It's unlikely that you will want to change this.
	const ssn_regex = /([^0-9\-\.\/\\%_]|^)\0?[0-6](\0?[0-9]){2}\0?[\.\-[:blank:]](\0?[0-9]){2}\0?[\.\-[:blank:]](\0?[0-9]){4}([^0-9\-\.=\/\\%_]|$)/ &redef;

	## Separators for SSNs to assist in validation.  It's unlikely that you
	## will want to change this.
	const ssn_separators = /\...\./ | 
	                       /\-..\-/ | 
	                       /[:blank:]..[:blank:]/ &redef;

	## The character used for redaction to replace all numbers.
	const redaction_char = "X" &redef;

	## The number of bytes around the discovered and redacted SSN that is used 
	## as a summary in notices.
	const redaction_summary_length = 200 &redef;
}

# The internal list of "known SSNs" which is populated through the intelligence framework.
global ssn_list: set[string] = {};

type InputVal: record {
	s: string;
};

event line(description: Input::EventDescription, tpe: Input::Event, s: string)
{
    add ssn_list[s];
}

event zeek_init() &priority=5
{
    # Create the new ssn_exposure logging stream
	Log::create_stream(SsnExposure::LOG, [$columns=Info, $path="ssn_exposure_payload"]);

    # Add ssn-exposure event if the SSN static file was provided
    # Issue #2: It turns out Corelight as of 1.15 does not support Input::add_event() in bro_init()
    # We're disabling this code for now since we're not reading in SSN files anyway .
    #	if ( ssn_file != "" )
    #		{
    #		Input::add_event([$source=ssn_file, 
    #		                  $name="ssn-exposure", 
    #		                  $reader=Input::READER_RAW,
    #		                  $mode=Input::REREAD,
    #		                  $want_record=F,
    #		                  $fields=InputVal,
    #		                  $ev=line]);
    #		}
}

# This function is used for validating and notifying about SSNs in a string.
function check_ssns(c: connection, data: string, f: fa_file): bool
{
	local ssnps = find_all(data, ssn_regex);
    local state_rec: StateRange;

	for ( ssnp in ssnps )
	{
		# Remove non-numeric character at beginning and end of string.
		ssnp = sub(ssnp, /^[^0-9]*/, "");
		ssnp = sub(ssnp, /[^0-9]*$/, "");

		if ( ssn_separators !in ssnp )
			next;

		# Remove all non-numerics
		local clean_ssnp = gsub(ssnp, /[^0-9]/, "");

		# Strip off any leading chars
		local ssn = sub_bytes(clean_ssnp, |clean_ssnp|-8, 9);

        # Check if SSN matches the defined prefixes
		local it_matched = F;
		if ( |prefixes| > 0 )
		{
            # Extract the 3 digit prefix for comparison
			local ssn_prefix_test = to_count(sub_bytes(ssn, 0, 3));
			for ( prefix in prefixes )
			{
				if ( ssn_prefix_test >= prefix$low &&
				     ssn_prefix_test <= prefix$high )
                {
					it_matched = T;
                    state_rec = prefix;
                }
			}
		}
		
        # Check to see if SSN is in predefined list (if provided by user)
		if ( |ssn_list| > 0 && ssn in ssn_list )
		{
			it_matched = T;
		}
		
        # SSN string was found
		if ( it_matched )
		{
            # print fmt("HTTP: %s", f$http$uri);
            # Split string and include the seperator (i.e. SSN string)
			local parts = split_string_all(data, ssn_regex);
            # print fmt("PARTS: %s", parts);
			local ssn_match = "";
			local redacted_ssn = "";

			# Take a copy to avoid modifying the vector while iterating.
			for ( i in copy(parts) )
			{
                # Odd-indexed elements do match the pattern and even-indexed ones do not	
                # https://www.bro.org/sphinx/scripts/base/bif/strings.bif.bro.html#id-split_string_all
                # Switched to odd indexed check here (bug fix from Seth Hall code) which was originally
                # performing redaction on even indexed elements, which was not properly masking the SSN
				if ( i % 2 == 1 )
				{
					# Redact all SSN matches and save one back for 
					# finding it's location.
					ssn_match = parts[i];
                    # Redact the SSN and save back to the vector
					parts[i] = gsub(parts[i], /[0-9]/, redaction_char);
					redacted_ssn = parts[i];
				}
			}

			local redacted_data = join_string_vec(parts, "");
			local ssn_location = strstr(data, ssn_match);

			local begin = 0;
			if ( ssn_location > (redaction_summary_length/2) )
				begin = ssn_location - (redaction_summary_length/2);
			
			local byte_count = redaction_summary_length;
			if ( begin + redaction_summary_length > |redacted_data| )
				byte_count = |redacted_data| - begin;

			local trimmed_data = sub_bytes(redacted_data, begin, byte_count);

            # Redact notice sub ssn
            # Using sub_bytes here since string_fill seems to always put a NUL at the end of the string
            # So we strip that off 
            local notice_sub_ssn = sub(ssnp, /[0-9]{4}$/, sub_bytes(string_fill(5, redaction_char), 0, 4));

            local msg_tmp = "";
            local msg_payload_source = f?$source ? f$source : "Unknown";

            # Draft notice message tailored to detection source (e.g. HTTP source)
            # TODO: Add additional modifications for other detection sources (FTP)
            if(f?$http) # HTTP source detection
            {
                local msg_host = f$http?$host ? f$http$host : cat(c$id$resp_h); 
                local msg_uri = f$http?$uri ? f$http$uri : "-Unknown-";
                msg_tmp = fmt("%s (%s), Source: %s, URI: %s%s", notice_sub_ssn, state_rec$state, msg_payload_source, msg_host, msg_uri);
            } 
            else if(c?$smb_state) # SMB/CIFS source detection
            {
                local smb_file: string = "unknown";
                local smb_file_action: string = "unknown";
                if(c$smb_state?$current_cmd && c$smb_state$current_cmd?$referenced_file && c$smb_state$current_cmd$referenced_file?$name)
                {
                    smb_file = c$smb_state$current_cmd$referenced_file$name;
                }

                if(c$smb_state?$current_cmd && c$smb_state$current_cmd?$referenced_file && c$smb_state$current_cmd$referenced_file?$action)
                {
                    # SMB::Action is of type enum. Convert to string.
                    smb_file_action = fmt("%s", c$smb_state$current_cmd$referenced_file$action);
                }

                msg_tmp = fmt("%s (%s), Source: %s, Action: %s, File: %s", notice_sub_ssn, state_rec$state, msg_payload_source, smb_file_action, smb_file);
            }
            else # All other source detection
            {
                msg_tmp = fmt("%s (%s), Source: %s", notice_sub_ssn, state_rec$state, msg_payload_source);
            }

			NOTICE([$note=Found,
			        $conn=c,
                    $msg=fmt("Possible SSN found: %s", msg_tmp),
			        $sub=fmt("Redacted excerpt of disclosed SSN session: %s", trimmed_data),
			        $identifier=cat(c$id$orig_h,c$id$resp_h),
                    $suppress_for=2hr]);

			local log: Info = [$ts=network_time(), 
			                   $uid=c$uid, $id=c$id,
			                   $ssn=(redact_log ? redacted_ssn : ssn_match),
			                   $data=(redact_log ? redacted_data : data)];

			Log::write(SsnExposure::LOG, log);

			return T;
		}
	}
	return F;
}


event SsnExposure::stream_data(f: fa_file, data: string)
{
	local c: connection;
	for ( id in f$conns )
	{
		c = f$conns[id];
		break;
	}

	if ( c$start_time > network_time()-10secs )
    {
		check_ssns(c, data, f);
    }
}

event file_new(f: fa_file)
{
    # The analysis of a new file has begun. Add a new analyzer to process the payload. 
	Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=SsnExposure::stream_data]);
}
