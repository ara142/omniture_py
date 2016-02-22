from datetime import date, timedelta
from collections import defaultdict
import urllib2, time, binascii, hashlib, json

class OmniturePy:
    
    
    def __init__(self, user_name, shared_secret, app_id, app_secret):
        self.user_name = user_name
        self.shared_secret = shared_secret
        self.app_id = app_id
        self.app_secret = app_secret
        
    def encodeUserData(self, user, password):
        return "Basic " + (user + ":" + password).encode("base64").rstrip()
        
    
    def __get_xwsse_header(self):
        nonce = str(time.time())
        base64nonce = binascii.b2a_base64(binascii.a2b_qp(nonce))
        created_date = time.strftime("%Y-%m-%dT%H:%M:%SZ",  time.gmtime())
        sha_object = hashlib.sha1(nonce + created_date + self.shared_secret).digest()
        password_64 = binascii.b2a_base64(sha_object)
        
        return 'UsernameToken Username="%s", PasswordDigest="%s", Nonce="%s", Created="%s"' % (self.user_name, password_64.strip(), base64nonce.strip(), created_date)
        
    
    def __get_access_token(self):
        token_url = "https://api.omniture.com/token"
        payload = "grant_type=client_credentials"
        req = urllib2.Request(token_url, data = payload)
        req.add_header('Authorization', self.encodeUserData(self.app_id, self.app_secret))
        res = urllib2.urlopen(req)
        x = res.read()
        return str(json.loads(x)['access_token'])
    
    
    def run_omtr_immediate_request(self, method, request_data = 0):
        """Send a request to the Omniture REST API
        Parameters:
        method-- The Omniture Method Name (ex. Report.QueueTrended, Company.GetReportSuites)
        request_data-- Details of method invocation, in Python dictionary/list form.
        """
        #request_data = {'access_token' : self.__get_access_token()}
        request = urllib2.Request('https://api.omniture.com/admin/1.4/rest/?method=%s' % method, json.dumps(request_data))
        request.add_header('Authorization', self.__get_access_token())
        request.add_header('host',  'api.omniture.com')
        request.add_header('X-WSSE',self.__get_xwsse_header())
        request.add_header('Content-Type',' application/json')
        return  json.loads(urllib2.urlopen(request).read())
    
    def run_omtr_queue_and_wait_request(self, method, request_data):
        """Send a report request to the Omniture REST API, and wait for its response.  
         Omniture is polled every 10 seconds to determine if the response is ready.  When the response is ready, it is returned.
        Parameters:
        method-- The Omniture Method Name (ex. Report.QueueTrended, Report.QueueOvertime)
        request_data-- Details of method invocation, in Python dictionary/list form.
        max_polls-- The max number of times that Omniture will be polled to see if the report is ready before failing out.
        max_retries-- The max number of times that we allow Omniture to report a failure, and retry this request before throwing an Exception.
        """
        status = "NA"
        status_resp = ""
        num_retries=0
        try:
            status_resp = self.run_omtr_immediate_request(method, request_data)
            report_id = status_resp['reportID']
            print "Report ID %s is in the Queue" % (report_id)
            report_query = {'reportID':"%s"% (report_id)} 
            status = "queued"
        except:
            status = "failed"
            raise Exception("Error: Omniture Report Run Failed ")
        
        
        while status == 'queued' or status == 'running':
            time.sleep(2)
            queue = self.run_omtr_immediate_request('Report.GetQueue', '')
            
            if queue:
                if str(report_id) in pd.DataFrame(queue)['reportID'].tolist():
                    status = 'running'
                    
                elif str(report_id) not in pd.DataFrame(queue)['reportID'].tolist():
                    
                    status = 'ready'
                    
                    
            else:
                
                status = 'ready'
                
        
        return self.run_omtr_immediate_request('Report.Get',report_query)    
