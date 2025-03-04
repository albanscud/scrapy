# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy

class CertAlertItem(scrapy.Item):
    titre = scrapy.Field()
    date = scrapy.Field()
    description = scrapy.Field()
    lien = scrapy.Field()

pass
