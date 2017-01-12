#include <stdio.h>

#include <Client_DSSE.h>
#include <DSSE_Param.h>
#include <Miscellaneous.h>
#include "net.h"
#include "CTokenInfo.h"

#include <fstream>

using namespace std;
vector<TYPE_COUNTER> gt;

void printMenu();

string exec(const char* cmd);

bool fexists(string filename_with_path)
{
  ifstream ifile(filename_with_path.c_str());
  return ifile;
}

bool is_number(const std::string& s)
{
    return !s.empty() && std::find_if(s.begin(), 
        s.end(), [](char c) { return !std::isdigit(c); }) == s.end();
}

void searchNon_existed_keywords(Client_DSSE* client_dsse)
{
    double start_time = 0 , end_time = 0 , elapsed = 0 ;
    set<string>::iterator iter;
    string word;
    TYPE_COUNTER i = 0;
    start_time = getCPUTime();
    stringstream cmd;
    string res;
    
    TYPE_COUNTER no;
    for(iter=client_dsse->keywords_dictionary.begin();iter != client_dsse->keywords_dictionary.end();iter++) 
    {
        if(i>client_dsse->keywords_dictionary.size()-800)
            break;
        if(i%500==0)
        {
            end_time = getCPUTime();
            elapsed = 1000.0 * (end_time - start_time);
            start_time = getCPUTime();
            printf("%lu Non-existing keywords searched ...\n",i);
            printf("Time cost: %g ms \n",elapsed);

        }
        if(i<client_dsse->keywords_dictionary.size()-1001)
        {
            i++;
            continue;
        }
        cout<<word;
        i++;
        word = *iter;
        
        if(is_number(word))
            continue;
        std::transform(word.begin(),word.end(),word.begin(),::toupper);
        for(int j = 0 ; j < 100; j ++)
        {
            no = 0;
            if(j%50==0)
                cout<<j<<" repeated searched!.."<<endl;
            //client_dsse->searchKeyword(word,no);
            if(no !=0)
            {
                cout<<j<<endl;
                cout<<word<<endl;
                cout<<"error:\t\t"<<no<<endl;
                cout<<"Press any key to continue....\n";
                cin.get();
            }
        }
    }
}
void searchExisted_keywords(Client_DSSE* client_dsse)
{
    double start_time = 0 , end_time = 0 , elapsed = 0 ;
    set<string>::iterator iter;
    string word;
    int i = 0;
    start_time = getCPUTime();
    stringstream cmd;
    string res;
    
    TYPE_COUNTER number;
    TYPE_COUNTER real_num;
    
    for(iter=client_dsse->keywords_dictionary.begin();iter != client_dsse->keywords_dictionary.end();iter++) 
    {
        if(i%500==0)
        {
            end_time = getCPUTime();
            elapsed = 1000.0 * (end_time - start_time);
            start_time = getCPUTime();
            printf("%d keywords searched ...\n",i);
            printf("Time cost: %g ms \n",elapsed);
        }

        word = *iter;
        if(strlen(word.c_str())<=0)
        {
            continue;
        }
        
        number = 0 ;
        //client_dsse->searchKeyword(word,number);
        
        
        //Compare with the ground truth

        // call the grep to compare

        cmd.str("");
        cmd.clear();
        cmd<<"LC_ALL=C fgrep -i -rwm 1 \""<<word<<"\" "<< gcsFilepath<<" | wc -l";
        res = exec(cmd.str().c_str());
        if(strlen(res.c_str())<=0)
            continue;
         real_num = stoi(res);
        
        if(real_num !=number)
        {
            cout<<word<<endl;
            cout<<"our scheme:\t\t"<<number<<endl;
            cout<<"grep:\t\t"<<real_num<<endl;
            cin.get();
        }

        
        i++; 
         
    }
}
int runTest()
{
    string search_word;
    Miscellaneous misc;
    std::string update_loc = gcsUpdateFilepath;
    vector<string> adding_files;
    TYPE_COUNTER i;
    ifstream input;
    
    for (int i = 1 ; i <=8; i ++)
    {
        stringstream file;
        file<<"/home/daniellin/Desktop/BeforeAdd/result_chunk"<<i<<".txt";
        input.open(file.str().c_str());
        TYPE_INDEX in = 0;
        while(input>>in)
        {
            gt.push_back(in);
        }
        input.close();
    }
    
    misc.extract_file_names(adding_files, update_loc);	
    
    /*
     * 0. Initialization
     */
     Client_DSSE*  client_dsse = new Client_DSSE();
        
     /*
      * 0.1 Generate new Master key for client as Gen in SAC;
      */ 
    client_dsse->genMaster_key();
    client_dsse->createEncrypted_data_structure();
    
    printf("Test begin:...\n");
    cin.get();    
    for(i = 0 ; i <adding_files.size();i++)
    {   
        if(i%5000==0 && i > 0)
        {
            printf("Test case 1:... times %d \n", (int)(i/5000));
            printf("5000 files added, performing search...\n");
            searchExisted_keywords(client_dsse);
            
            searchNon_existed_keywords(client_dsse);
        }
        //client_dsse->addFile(adding_files[i],update_loc);
    }
    //Test Case 4: Delete each 1000 files before performing search until end
    printf("Test case 2:...\n");
    cin.get();
    /* Load the ground truth to test */
    
    gt.clear();
    for (int i = 1 ; i <=8; i ++)
    {
        stringstream file;
        file<<"/home/daniellin/Desktop/AfterAdd/result_chunk"<<i<<".txt";
        input.open(file.str().c_str());
        TYPE_INDEX in = 0;
        while(input>>in)
        {
            gt.push_back(in);
        }
        input.close();
    }
    
    
    for(i = 0 ; i <adding_files.size();i++)
    {
        
        if(i%3000==0 && i >0)
        {
            printf("Test case 3:...times %d\n",(int)i/3000);
            printf("1000 files deleted, performing search...\n");
            searchExisted_keywords(client_dsse);
            
            searchNon_existed_keywords(client_dsse);
        }
         
        //client_dsse->delFile(adding_files[i],update_loc);
    }
    printf("Test case 4:...\n");
    cin.get();  
    
    /* Load the ground truth to test */
    
    gt.clear();
    for (int i = 1 ; i <=8; i ++)
    {
        stringstream file;
        file<<"/home/daniellin/Desktop/BeforeAdd/result_chunk"<<i<<".txt";
        input.open(file.str().c_str());
        TYPE_INDEX in = 0;
        while(input>>in)
        {
            gt.push_back(in);
        }
        input.close();
    }
    
    
    searchExisted_keywords(client_dsse);
            
    searchNon_existed_keywords(client_dsse);
    
    return 0;
}
#define PEER_ADDRESS "192.168.123.141"
#define PEER_PORT 4433
#include "zmq.hpp"
using namespace zmq;
int main(int argc, char **argv)
{

	string search_word;
    Miscellaneous misc;
    std::string update_loc = gcsUpdateFilepath;
    string updating_filename;
    
    TYPE_COUNTER search_result;
    setbuf(stdout,NULL);
    
    /*
     * 0. Initialization
     */
     
     
     Client_DSSE*  client_dsse = new Client_DSSE();
     
     /*
      * 0.1 Generate new Master key for client as Gen in SAC;
      */ 
     // client_dsse->genMaster_key();
    
    /*
     * 1. Client generates the encrypted data structure according to given list of files
     */
  /*  string str_keyword;
    
    while (1)
    {
        int selection =-1;
        do
        {
            printMenu();
            cout<<"Select your choice: ";
            while(!(cin>>selection))
            {
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(),'\n');
                cout<<"Invalid input. Try again: ";
            }
            
        }while(selection < 0 && selection >4);
        switch(selection)
        {
        case 0:
            client_dsse->genMaster_key();
            break;
        case 1:
            client_dsse->createEncrypted_data_structure();
            break;
        case 2:
            cout<<"Keyword search: ";
            cin>>str_keyword;
             std::transform(str_keyword.begin(),str_keyword.end(),str_keyword.begin(),::tolower);
            client_dsse->searchKeyword(str_keyword,search_result);
            cout<<"Keyword "<<str_keyword.c_str()<<" appears in "<<search_result<<" files!"<<endl;
#if (defined(SEND_SEARCH_FILE_INDEX) || !defined(CLIENT_SERVER_MODE))
            if(search_result>0)
            {
                cout<<"See "<<gcsDataStructureFilepath<<FILENAME_SEARCH_RESULT<<" for file ID specification!"<<endl;
                
            }
#endif
            break;
        case 3:
            cout<<"Specify the filename want to add: ";
            cin>>updating_filename;
            if(!fexists(gcsUpdateFilepath+updating_filename))
            {
                cout<<endl<<"File not found! Please put/check the file into/in update folder"<<endl;
                break;
            }
            client_dsse->addFile(updating_filename,gcsUpdateFilepath);
            break;
        case 4:
            cout<<"Specify the filename want to delete: ";
            cin>>updating_filename;
            client_dsse->delFile(updating_filename,gcsUpdateFilepath);
            break;
        default:
            break;
        }
    }
*/
    client_dsse->genMaster_key();
    client_dsse->createEncrypted_data_structure();
    TYPE_COUNTER s = 0;
    //client_dsse->searchKeyword("the",s);
    for(int i = 0 ; i < 5 ; i++)
    {
        cin.get();
        client_dsse->operation(SEARCH_OPERATION,"the");
        //client_dsse->operation(OP_ADD_FILE,"/home/daniellin/Desktop/add_small/6");
        //client_dsse->operation(SEARCH_OPERATION,"the");
        //client_dsse->operation(OP_DELETE_FILE,"/the/daniellin/Desktop/small/1");
        //client_dsse->operation(SEARCH_OPERATION,"home");
         
    } 
/*
    int server_fd =1;
    unsigned char buffer_out[SOCKET_BUFFER_SIZE]="dsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    unsigned char buffer_in[SOCKET_BUFFER_SIZE];
    
    memset(buffer_out,0,SOCKET_BUFFER_SIZE);
    memset(buffer_in,0,SOCKET_BUFFER_SIZE);
    
    
    double avg = 0;
   
for(int i = 0 ; i < 1000;i++)
{
    auto start = time_now;
    zmq::context_t context(1);
    zmq::socket_t socket(context,ZMQ_REQ);
    
    socket.connect(PEER_ADDRESS_0);
    //net_connect(&server_fd,PEER_ADDRESS,PEER_PORT);
        
    //net_send(&server_fd,buffer_out,SOCKET_BUFFER_SIZE);
    //net_recv(&server_fd,buffer_in,SOCKET_BUFFER_SIZE);
    socket.send(buffer_out,SOCKET_BUFFER_SIZE);
    socket.recv(buffer_in,SOCKET_BUFFER_SIZE);
        
    
    auto end = time_now;
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start) ;
    double total_time = elapsed.count() / 1000.0;
    printf("Time: %8.4f ms\n",total_time);
    //net_close(server_fd);
    socket.close();
    avg+=total_time;
}   
    cout<<"average: "<<avg/1000<<endl;
    misc.print_ucharstring(buffer_in,SOCKET_BUFFER_SIZE);
    return 0;
  */  
}
void printMenu()
{
    cout<<"---------------"<<endl<<endl;
    cout<<"0. (Re)generate keys"<<endl;
    cout<<"1. (Re)build data structure"<<endl;
    cout<<"2. Keyword search: "<<endl;
    cout<<"3. Add files"<<endl;
    cout<<"4. Delete files"<<endl<<endl;;
    cout<<"---------------"<<endl;
}

string exec(const char* cmd)
{
    std::shared_ptr<FILE> pipe(popen(cmd,"r"),pclose);
    if(!pipe) return "ERROR";
    char buffer[128];
    string result = "";
    while(!feof(pipe.get()))
    {
        if(fgets(buffer,128,pipe.get())!=NULL)
        {
            result += buffer;
        }
    }
    return result;
}

