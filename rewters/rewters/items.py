# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy

class IocItem(scrapy.Item):
    type = scrapy.Field()
    value = scrapy.Field()

pass
