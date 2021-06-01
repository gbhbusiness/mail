import pprint
import werkzeug

from odoo import http
from odoo.http import request

import logging
_logger = logging.getLogger(__name__)


class RedsysController(http.Controller):

    @http.route([
        '/payment/redsys/return',
        '/payment/redsys/cancel',
        '/payment/redsys/error',
        '/payment/redsys/reject',
    ], type='http', auth='none', csrf=False)
    def redsys_return(self, **post):
        _logger.info('Redsys: entering form_feedback with post data %s', pprint.pformat(post))
        if post:
            request.env['payment.transaction'].sudo().form_feedback(post, 'redsys')
        return_url = post.pop('return_url', '') or '/shop'
        return werkzeug.utils.redirect(return_url)

    @http.route([
        '/payment/redsys/result/notifications',
        '/payment/redsys/result/ok',
        '/payment/redsys/result/ko',
        ], type='http', auth='public', methods=['GET'], website=True)
    def redsys_result(self, **post):
        if post:
            _logger.info('Redsys result: entering form_feedback with post data %s', pprint.pformat(post))
            request.env['payment.transaction'].sudo().form_feedback(post, 'redsys')
        return werkzeug.utils.redirect('/payment/process')
