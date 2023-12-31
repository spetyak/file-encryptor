#-----------------------------------------------------------------------------
# Lab 11 Makefile
#-----------------------------------------------------------------------------

#-----------------------------------------------------------------------------
# Choose a compiler and its options
#--------------------------------------------------------------------------
CC   = gcc
OPTS = -O0
DEBUG = -g

#--------------------------------------------------------------------------
# Add the names of the directories (Add them after each ./)
#--------------------------------------------------------------------------
SRCDIR=./src
OBJDIR=./obj
INCDIR=./inc
BINDIR=.

#--------------------------------------------------------------------
# Add the rest of the source files. Don't forget to add the '\' character
# to continue the line. You don't need it after the last source file.
# Note: The source directory, $(SRCDIR), needs to be given for each
# individual file. The $(SRCDIR) below shows how it is done for the
# aes.c file. Also note that there should only be one SRCS= (i.e. don't
# add more of them as you add files).
#--------------------------------------------------------------------
SRCS=$(SRCDIR)/aes.c $(SRCDIR)/parse.c $(SRCDIR)/encrypt.c $(SRCDIR)/decrypt.c \
$(SRCDIR)/cbc.c

#--------------------------------------------------------------------
# You don't need to edit the next few lines. They define other flags
# used in the compilation of the source code
#--------------------------------------------------------------------
INCLUDE = $(addprefix -I,$(INCDIR))
OBJS=$(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
CFLAGS   = $(OPTS) $(INCLUDE) $(DEBUG)

#--------------------------------------------------------------------
# Add the name of the executable after the $(BINDIR)/
#--------------------------------------------------------------------
TARGET = $(BINDIR)/aes

all: $(TARGET)

$(TARGET): $(OBJS) 
	$(CC) $(CFLAGS) -o $@ $(OBJS)

$(OBJS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

#--------------------------------------------------------------------
# This clean target will remove all the object files, but
# not the executable
#--------------------------------------------------------------------
clean:
	rm -f $(OBJS)

#--------------------------------------------------------------------
# Add a target below named cleanall that will remove the object files
# as well as the executable
#--------------------------------------------------------------------
cleanall:
	rm -f $(OBJS) $(BINDIR)/aes
