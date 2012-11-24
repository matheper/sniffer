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

class App(object):
    """Sniffer Interface
    """

    def __init__(self):
        #carrega o arquivo Glade
        self.arquivoglade = "app.glade"
        #carrega xml
        self.xml = gtk.glade.XML(self.arquivoglade)
        self.xml.signal_autoconnect(self)

        #Campo Tree
        self.lstConsulta = self.xml.get_widget("lstConsulta")
        self.lstConsulta.set_headers_visible(True)

        self.sniffer = Sniffer()
    
    def start(self, widget, data):
        """ Start a capitura das pacotes
        """

        #Formata controle lista
        self.ClearColunas()
        self.listbox_types = [str,str,str,str,str,str,str,str]
        self.listbox_data = self.sniffer.capture_list
        self.lstConsulta.set_model(self.get_dados(self.listbox_data, self.listbox_types))

        #Cria colunas da lista
        self.listbox_header = [('IP Origem',0),('IP Destino',1),('ID Próximo Cabeçalho',2),
                               ('Próximo Cabeçalho',3),('Hop Limit',4),('ID Classe de Tráfego',5),
                               ('Controle Classe',6), ('Descricao Classe',7)
                              ]
        self.CriarColuna(self.listbox_header)
        self.sniffer.configure_device()

    def stop(self, widget, data):
        """ Stop a capitura das pacotes
        """
        self.ClearColunas()

    def filter(self, widget, data):
        """ Filtra os pacotes
        """
        print 'filter ok'
        self.sniffer.get_next_packet()
        self.listbox_data = self.sniffer.capture_list
        self.listbox_update()

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

    def listbox_update(self):
        self.lstConsulta.set_model(self.get_dados(self.listbox_data, self.listbox_types))


if __name__ == "__main__":
    app = App()
    gtk.main()
