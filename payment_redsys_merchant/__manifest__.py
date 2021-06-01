# -*- coding: utf-8 -*-
#################################################################################
##    Copyright (c) 2020-Present Webkul Software Pvt. Ltd. (<https://webkul.com/>)
#    You should have received a copy of the License along with this program.
#    If not, see <https://store.webkul.com/license.html/>
#################################################################################
{
    "name"                 :  "Website Redsys Payment Acquirer",
    "summary"              :  "Intigration of Redsys payment gateway for accepting payments in Odoo.",
    "category"             :  "Website/Payment Acquirer",
    "version"              :  "1.0.1",
    "sequence"             :  1,
    "author"               :  "Webkul Software Pvt. Ltd.",
    "license"              :  "Other proprietary",
    "website"              :  "https://store.webkul.com/",
    "description"          :  """ Odoo Redsys Merchant Payment Acquirer
                                Odoo Redsys Payment Gateway
                                Payment Gateway
                                Redsys
                                Redsys integration
                                Payment acquirer
                                Payment processing
                                Payment processor
                                Website payments
                                Sale orders payment
                                Customer payment
                                Integrate Redsys payment acquirer in Odoo
                                Integrate Redsys payment gateway in Odoo""",
    "live_test_url"        :  "http://odoodemo.webkul.com/?module=payment_redsys_merchant&version=13.0&lout=0&custom_url=/shop",
    "depends"              :  ['payment'],
    "data"                 :  [
                             'views/redsys_payment_view.xml',
                             'views/redsys_templates.xml',
                             'data/payment_acquirer_data.xml',
                            ],
    "external_dependencies": {
        "python": [
            "pycryptodome",
        ],
    },
    "images"               :  ['static/description/Banner.png'],
    "application"          :  True,
    "installable"          :  True,
    "auto_install"         :  False,
    "price"                :  69,
    "currency"             :  "USD",
}
