# coding: utf-8

import pprint
import hashlib
import hmac
import base64
import json
import urllib
import binascii

from odoo import http, api, fields, models, _
from odoo.addons.payment.models.payment_acquirer import ValidationError
from odoo.tools import config
from odoo.tools.float_utils import float_compare
# from odoo.tools.safe_eval import safe_eval
from odoo.tools.float_utils import float_round
import logging
_logger = logging.getLogger(__name__)

from .currency_code import currency_dict

try:
    from Crypto.Cipher import DES3
except ImportError:
    _logger.info("\n Payment Redsys:.......ERROR.>> Missing dependency (pycryptodome)..Please Install if first using command.'pip3 install pycryptodome'............")

class PaymentAcquirerRedsys(models.Model):
    _inherit = 'payment.acquirer'

    provider = fields.Selection(selection_add=[('redsys', 'Redsys')], ondelete={'redsys': 'set default'})
    redsys_merchant_code = fields.Char("Merchant Code", required_if_provider='redsys', groups='base.group_user')
    redsys_merchant_key = fields.Char("Merchant Key", required_if_provider='redsys', groups='base.group_user')
    redsys_transaction_type = fields.Char('Transtaction Type', default='0', required_if_provider='redsys', readonly=True)
    redsys_merchant_terminal = fields.Char("Merchant Terminal", default='001', required_if_provider='redsys', help="Terminal number assigned by your bank.", groups='base.group_user')
    redsys_pay_method = fields.Char("Payment Methods", default="T")
    redsys_signature_version = fields.Char("Signature Version", default='HMAC_SHA256_V1', readonly=True)
    redsys_merchant_lang = fields.Selection(
        [
            ("001", "Spanish"),
            ("002", "Inglés"),
            ("003", "Catalán"),
            ("004", "Francés"),
            ("005", "Alemán"),
            ("006", "Holandés"),
            ("007", "Italiano"),
            ("008", "Sueco"),
            ("009", "Portugués"),
            ("010", "Valenciano"),
            ("011", "Polaco"),
            ("012", "Gallego"),
            ("013", "Euskera"),
            ("2", "English - English"),
        ],
        "Merchant Consumer Language",
        default="2")

    def encodeInBase64(self,dataString):
        base64Bytes = base64.b64encode(dataString.encode())
        base64String = base64Bytes.decode()
        return base64String

    def _decodeFromBase64(self,encodedParams):
        base64Bytes = base64.b64decode(encodedParams)
        params = json.loads(base64Bytes.decode())
        return params

    def _generate_merchant_parameters(self,tx_values):
        
        base_url = self._get_website_url()

        currency = tx_values.get('currency',False)
        if currency and currency.name in currency_dict:
            currency_code = currency_dict.get(currency.name,False)
        else:
            currency_code = False
            msg = "Currency <" + currency_code + "> not Found" if currency_code else "Currency <" + currency_code + "> not Found in Currency dict"
            raise ValidationError(msg)

        params = {
            "Ds_Merchant_Amount"            : str(int( tx_values['amount'] * 100 )),
            "Ds_Merchant_Currency"          : currency_code and str(currency_code) and "978",
            "Ds_Merchant_MerchantCode"      : str(self.redsys_merchant_code) or "999008881",
            "Ds_Merchant_Order"             : tx_values['reference'] or False,
            "Ds_Merchant_Terminal"          : str(self.redsys_merchant_terminal) or "001",
            "Ds_Merchant_TransactionType"   : int(self.redsys_transaction_type) or "0",
            'Ds_Merchant_MerchantUrl'       : '%s/payment/redsys/result/notifications' % (base_url),
            "Ds_Merchant_ConsumerLanguage"  : (self.redsys_merchant_lang or "001"),
            "Ds_Merchant_Paymethods"        : self.redsys_pay_method or "T",
            "Ds_Merchant_UrlOk"             :'%s/payment/redsys/result/ok' % (base_url),
            "Ds_Merchant_UrlKo"             :'%s/payment/redsys/result/ko' % (base_url),
        }
        base64String = self.encodeInBase64(json.dumps(params, separators=(",", ":")))
        return base64String

    def _generateDsSignature(self, secret_key, encodedParam):
        params = self._decodeFromBase64(encodedParam)
        if 'Ds_Merchant_Order' in params:
            order = str(params['Ds_Merchant_Order'])
        else:
            order = str(urllib.parse.unquote(params.get('Ds_Order', 'Not found')))
        cipher = DES3.new(
            key=base64.b64decode(secret_key),
            mode=DES3.MODE_CBC,
            IV=b'\0\0\0\0\0\0\0\0')
        diff_block = len(order) % 8
        zeros = diff_block and (b'\0' * (8 - diff_block)) or b''
        key = cipher.encrypt(str.encode(order + zeros.decode()))
        if isinstance(encodedParam, str):
            encodedParam = encodedParam.encode()
        dig = hmac.new(
            key=key,
            msg=encodedParam,
            digestmod=hashlib.sha256).digest()
        return base64.b64encode(dig).decode()

    def redsys_form_generate_values(self, tx_values):
        self.ensure_one()
        merchant_parameters = self._generate_merchant_parameters(tx_values)
        tx_values.update({
            'Ds_SignatureVersion': str(self.redsys_signature_version),
            'Ds_MerchantParameters': merchant_parameters,
            'Ds_Signature': self._generateDsSignature(self.redsys_merchant_key, merchant_parameters),
        })
        return tx_values

    def redsys_get_form_action_url(self):
        """ Provide Post Url For Redsys Payment Form ."""
        self.ensure_one()
       
        if self.state == "enabled":
            url = "https://sis.redsys.es/sis/realizarPago"
        else:
            url = "https://sis-t.redsys.es:25443/sis/realizarPago"
        return url

    api.model
    def _get_website_url(self):
        if config['test_enable']:
            return self.env['ir.config_parameter'].sudo().get_param(
                'web.base.url')
        domain = http.request.website.domain
        if domain and domain != 'localhost':
            base_url = '%s://%s' % (
                http.request.httprequest.environ['wsgi.url_scheme'],
                http.request.website.domain
            )
        else:
            base_url = self.env['ir.config_parameter'].sudo().get_param(
                'web.base.url')
        return base_url or ''

class PaymentTransactionRedsys(models.Model):
    _inherit = 'payment.transaction'

    redsys_txnid = fields.Char('Transaction ID')
    def merchant_params_form_data(self, data):
        parameters = data.get('Ds_MerchantParameters', '')
        return json.loads(base64.b64decode(parameters).decode())


    @api.model
    def _redsys_form_get_tx_from_data(self, data):
        """ Given a data dict coming from redsys, verify it and
        find the related transaction record. """
        parameters = self.merchant_params_form_data(data)
        reference = urllib.parse.unquote(parameters.get('Ds_Order', ''))
        pay_id = parameters.get('Ds_AuthorisationCode')
        shasign = data.get('Ds_Signature', '').replace('_', '/').replace('-', '+')
        test_env = http.request.session.get('test_enable', False)
        if not reference or not pay_id or not shasign:
            error_msg = 'Redsys: received data with missing reference (%s) or pay_id (%s) or shashign (%s)' % (reference, pay_id, shasign)
        tx = self.search([('reference', '=', reference)])
        if not tx:
            error_msg = 'Redsys: received data for reference %s' % (reference)
            if not tx:
                error_msg += '; no order found'
        else:
            latest_tx = tx[0]
            shasign_check = latest_tx.acquirer_id._generateDsSignature(latest_tx.acquirer_id.redsys_merchant_key, data.get('Ds_MerchantParameters', ''))
            if shasign_check != shasign:
                error_msg = (
                    'Redsys: invalid shasign, received %s, computed %s, '
                    'for data %s' % (shasign, shasign_check, data)
                )
                raise ValidationError(error_msg)
        return tx and latest_tx

    @api.model
    def _redsys_form_get_invalid_parameters(self, data):
        invalid_parameters = []
        parameters = self.merchant_params_form_data(data)

        if float_compare(float(parameters.get('Ds_Amount', '0.0')) / 100, self.amount, 2) != 0:
            invalid_parameters.append(('Amount', parameters.get('Ds_Amount'),'%.2f' % self.amount))

        return invalid_parameters

    @api.model
    def _get_redsys_status(self, status_code):
        if 0 <= status_code <= 100:
            return "done"
        elif status_code <= 203:
            return "pending"
        elif 912 <= status_code <= 9912:
            return "cancel"
        else:
            return "error"

    def _redsys_form_validate(self,  data):
        parameters = self.merchant_params_form_data(data)
        status_code = int(parameters.get('Ds_Response', '29999'))
        state = self._get_redsys_status(status_code)
        vals = {
            'state': state,
            'redsys_txnid': parameters.get('Ds_AuthorisationCode'),
            'date': fields.Datetime.now()
        }
        state_message = ""
        if state == 'done':
            vals['state_message'] = _('Ok: %s') % parameters.get('Ds_Response')
            self._set_transaction_done()
        elif state == 'pending':  # 'Payment error: code: %s.'
            state_message = _('Error: %s [%s]')
            self._set_transaction_pending()
        elif state == 'cancel':  # 'Payment error: bank unavailable.'
            state_message = _('Bank Error: %s [%s]')
            self._set_transaction_cancel()
        else:
            state_message = _('Redsys: feedback error %s [%s]')
            self._set_transaction_error(state_message)
        if state_message:
            vals['state_message'] = state_message % ( parameters.get('Ds_Response'), parameters.get('Ds_ErrorCode'))
            if state == 'error':
                _logger.warning(vals['state_message'])
        self.write(vals)
        return state != 'error'

    @api.model
    def form_feedback(self, data, acquirer_name):
        res = super(PaymentTransactionRedsys, self).form_feedback(data, acquirer_name)
        tx = False
        try:
            get_tx_method_name = '_%s_form_get_tx_from_data' % acquirer_name
            if hasattr(self, get_tx_method_name):
                tx = getattr(self, get_tx_method_name)(data)
            _logger.info('<%s> transaction processed: tx ref:%s', acquirer_name, tx.reference if tx else 'n/a',tx.amount if tx else 'n/a')
            if tx and tx.state == 'done':
                _logger.info('<%s> transaction completed, confirming order %s (ID %s)', acquirer_name, tx.sale_order_ids.name, tx.sale_order_ids.id)
                tx.sale_order_ids.with_context(send_email=True).action_confirm()
            elif (tx.state != 'cancel' and tx.sale_order_ids.state == 'draft'):
                _logger.info('<%s> transaction pending, sending quote email for order %s (ID %s)', acquirer_name, tx.sale_order_ids.name, tx.sale_order_ids.id)
                tx.sale_order_ids.force_quotation_send()
            else:
                _logger.warning('<%s> transaction MISMATCH for order %s (ID %s)', acquirer_name, tx.sale_order_ids.name, tx.sale_order_ids.id)
        except Exception:
            _logger.exception('Fail to confirm the order or send the confirmation email%s', tx and ' for the transaction %s' % tx.reference or '')
        return res
