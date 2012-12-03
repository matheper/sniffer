# -*- coding:utf-8 -*-
#!/usr/bin/python
import sys
import threading

try:
    import pygtk
    pygtk.require("2.0")
except:
    print "Erro require pygtk >= 2.0."
    sys.exit(1)
try:
    import gtk
    import gtk.glade
except:
    print "Erro ao importar o GTK."
    sys.exit(1)
try:
    from sniffer import Sniffer
except:
    print "Erro ao importar sniffer."
    sys.exit(1)
try:
    import cairoplot, cairo
except:
    print "Erro ao importar cairoplot."
    sys.exit(1)

class App(object):
    """Sniffer Interface
    """

    def __init__(self):
        #carrega o arquivo Glade
        self.appglade = "app.glade"
        #carrega xml
        self.xml = gtk.glade.XML(self.appglade)
        self.xml.signal_autoconnect(self)

        #Campo Tree
        self.lstConsulta = self.xml.get_widget("lstConsulta")
        self.entryFilter = self.xml.get_widget("entry1")
        self.lstConsulta.set_headers_visible(True)
        self.sniffer = Sniffer()
        self.format_grid()

    def start(self, widget, data):
        """ Start a captura dos pacotes
        """
        self.format_grid()

    def format_grid(self):
        #Formata controle lista
        self.ClearColunas()
        self.listbox_types = [str,str,str,str,str,str,str,str,str,str,str]
        self.listbox_data = self.sniffer.capture_list
        self.lstConsulta.set_model(self.get_dados(self.listbox_data, self.listbox_types))

        #Cria colunas da lista
        self.listbox_header = [ ('IP Origem',0), ('Tipo',1), ('IP Destino',2), ('Tipo',3),
                                ('Próximo Cabeçalho',4), ('Hop Limit',5),
                                ('Classe de Tráfego',6), ('',7), ('',8),
                                ('Flowlabel',9), ('Versão',10)
                              ]
        self.CriarColuna(self.listbox_header)

    def stop(self, widget, data):
        """ Stop a captura dos pacotes
        """
        self.ClearColunas()

    def filter(self, widget, data):
        """ Filtra os pacotes
        """
        self.listbox_data = self.sniffer.capture_filter(self.entryFilter.get_text())
        self.listbox_update()

    def clear(self, widget, data):
        self.listbox_data = self.sniffer.capture_list
        self.listbox_update()

    def load(self, widget, data):
        """Load file capture.cap."""
        self.sniffer.read_file('capture.cap')
        self.listbox_data = self.sniffer.capture_list
        self.listbox_update()

    def statistics(self, widget, data):
        self.open_graphs()

    def quitMainWindow(self, widget, data):
        """
            Sai do loop principal de eventos, finalizando o programa
        """
        gtk.main_quit()

    def CriarColuna(self, colunas):
        """ Cria coluna da lista
        """
        for coluna in colunas:
            titulo = coluna[0]
            id = coluna[1]
            renderer = gtk.CellRendererText()
            column = gtk.TreeViewColumn(titulo, renderer, text = id)
            column.set_resizable(False)
            self.lstConsulta.append_column(column)

    def ClearColunas(self):
        """ Clear coluna da lista
        """
        for coluna in self.lstConsulta.get_columns():
            self.lstConsulta.remove_column(coluna)

    def get_dados(self,dados,types):
        """ Add as linhas nas respectivas colunas
        """
        retorno = gtk.ListStore(*types)
        for dado in dados:
            retorno.append(dado)
        return retorno

    def read_file(self):
        self.sniffer.read_file('/home/matheus/Downloads/captura/captura_ipv6_filter')
        self.listbox_data = self.sniffer.capture_list
        self.listbox_update()

    def listbox_update(self):
        self.lstConsulta.set_model(self.get_dados(self.listbox_data, self.listbox_types))

    def create_graphs(self):
        self.sniffer.set_dicts()
        background = cairo.LinearGradient(300, 0, 300, 400)
        background.add_color_stop_rgb(0,0.4,0.4,0.4)
        background.add_color_stop_rgb(1.0,0.1,0.1,0.1)
        data = self.sniffer.next_header_dict
        cairoplot.donut_plot( "nextHeader.svg", data, 400, 200, gradient = True, shadow = True, inner_radius = 0.3 )
        data = self.sniffer.address_type_dict
        cairoplot.donut_plot( "addressType.svg", data, 400, 200, gradient = True, shadow = True, inner_radius = 0.3 )
        data = self.sniffer.traffic_class_dict
        cairoplot.donut_plot( "trafficClass.svg", data, 400, 200, gradient = True, shadow = True, inner_radius = 0.3 )


        data = self.sniffer.number_of_next_header
        x_labels = ["Quantidade de próximos cabeçalhos"]
        cairoplot.dot_line_plot("lenNextHeader.svg", data, 400, 200, axis = False, grid = True, x_labels = [' ',' '])


    def open_graphs(self):
        self.create_graphs()
        self.graphsglade = "graphs.glade"
        self.graphsxml = gtk.glade.XML(self.graphsglade)
        address = self.graphsxml.get_widget("addressType")
        address.set_from_file('addressType.svg')
        traffic = self.graphsxml.get_widget("trafficClass")
        traffic.set_from_file('trafficClass.svg')
        icmpv6 = self.graphsxml.get_widget("lenNextHeader")
        icmpv6.set_from_file('lenNextHeader.svg')
        nextHeader = self.graphsxml.get_widget("nextHeader")
        nextHeader.set_from_file('nextHeader.svg')


if __name__ == "__main__":
    app = App()
    gtk.main()
