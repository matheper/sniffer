# -*- coding:utf-8 -*-
#!/usr/bin/python
import sys

try:
    import pygtk
    pygtk.require("2.0")
except:
    print "Erro require pygtk >= 2.0"
    sys.exit(1)

try:
    import gtk
    import gtk.glade
except:
    print "Erro ao importar o GTK"
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
    
    def start(self, widget, data):
        """ Start a capitura das pacotes
        """

        #Formata controle lista
        self.ClearColunas()
        types = [str,str,str]
        dados = [('a','aa','aaa'),
                 ('b','bb','bbb'),
                 ('c','cc','ccc'),
                 ('d','dd','ddd')]
        self.lstConsulta.set_model(self.get_dados(dados, types))

        #Cria colunas da lista
        colunas = [('IP Origem',0),('IP Destino',1),('Tipo de Cabeçalho(s)',2)]
        self.CriarColuna(colunas)

    def stop(self, widget, data):
        """ Stop a capitura das pacotes
        """
        self.ClearColunas()

    def filter(self, widget, data):
        """ Filtra os pacotes
        """
        print 'filter ok'

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
 
if __name__ == "__main__":
    c = App()
    gtk.main()
