package com.example.controller;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import com.example.dto.MemberUser;
import com.example.dto.PrintingDTO;
import com.example.dto.PrintingSideDTO;
import com.example.dto.PsidePicSorting;
import com.example.dto.TshirtColorDTO;
import com.example.dto.TshirtPrintingSidePicViewDTO;
import com.example.dto.TshirtSizeDTO;
import com.example.entity.DesignOne;
import com.example.entity.File;
import com.example.entity.Member;
import com.example.entity.MemberAddress;
import com.example.entity.Orders;
import com.example.entity.Printing;
import com.example.entity.PrintingSide;
import com.example.entity.PsidePic;
import com.example.entity.TsDesignView;
import com.example.entity.Tshirt;
import com.example.entity.TshirtColor;
import com.example.entity.TshirtContentView;
import com.example.entity.TshirtImage;
import com.example.entity.TshirtPrintingSidePicView;
import com.example.entity.TshirtSize;
import com.example.entity.TshirtView01;
import com.example.repository.DesignOneRepository;
import com.example.repository.FileRepository;
import com.example.repository.MemberAddressRepository;
import com.example.repository.MemberRepository;
import com.example.repository.OrdersRepository;
import com.example.repository.PrintingRepository;
import com.example.repository.PrintingSideRepository;
import com.example.repository.PsidePicRepository;
import com.example.repository.TsDesignViewRepository;
import com.example.repository.TshirtColorRepository;
import com.example.repository.TshirtContentViewRepository;
import com.example.repository.TshirtImageRepository;
import com.example.repository.TshirtPrintingSidePicViewRepository;
import com.example.repository.TshirtRepository;
import com.example.repository.TshirtSizeRepository;
import com.example.repository.TshirtView01Repository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Controller
@Slf4j
@RequiredArgsConstructor
@RequestMapping(value = "/product")
public class HomeProductController {
    
    final TshirtImageRepository tiRepository;
    final PsidePicRepository ppRepository;
    final TshirtSizeRepository tsRepository;
    final PrintingRepository pRepository;
    final TshirtColorRepository tcRepository;
    final FileRepository fRepository;
    final PrintingSideRepository psRepository;
    final TshirtPrintingSidePicViewRepository tpspvRepository;
    final TshirtContentViewRepository tcvRepository;
    final ResourceLoader resourceLoader;

    final TsDesignViewRepository tsdvRepository;
    final TshirtView01Repository tView01Repository;
    final MemberRepository mRepository;
    final DesignOneRepository dOneRepository;
    
    final OrdersRepository ordersRepository;
    final MemberAddressRepository mAddressRepository;

    final TshirtRepository tRepository;
    final PsidePicRepository pspRepository;

    // 127.0.0.1:9090/CUSTOM/product/image?ino=1
    @GetMapping(value = "/image")
    public ResponseEntity<byte[]> image(@RequestParam(name = "ino", defaultValue = "0") BigInteger ino) throws IOException{
        TshirtImage obj = tiRepository.findById(ino).orElse(null);
        //log.info("objobj => {}", obj);
        HttpHeaders headers = new HttpHeaders(); // import org.springframework.http.HttpHeaders;
        if(obj != null){ // 이미지가 존재하는지 확인
            if(obj.getIsize() != null){
                headers.setContentType( MediaType.parseMediaType(obj.getItype()));
                return new ResponseEntity<>(obj.getIdata(), headers, HttpStatus.OK);
            }
        }
        // 이미지가 없을 경우
        InputStream is = resourceLoader.getResource("./img/no-image.png").getInputStream(); //?
        headers.setContentType(MediaType.IMAGE_PNG);
        return new ResponseEntity<>(is.readAllBytes(), headers, HttpStatus.OK);
    }

    @GetMapping(value = "/psidepic")
    public ResponseEntity<byte[]> psidepic(@RequestParam(name = "pspicno", defaultValue = "0") BigInteger pspicno) throws IOException{
        PsidePic obj = ppRepository.findById(pspicno).orElse(null);
        //log.info("objobj => {}", obj);
        HttpHeaders headers = new HttpHeaders(); // import org.springframework.http.HttpHeaders;
        if(obj != null){ // 이미지가 존재하는지 확인
            if(obj.getPspicsize() != null){
                headers.setContentType( MediaType.parseMediaType(obj.getPspictype()));
                return new ResponseEntity<>(obj.getPspicdata(), headers, HttpStatus.OK);
            }
        }
        // 이미지가 없을 경우
        InputStream is = resourceLoader.getResource("./img/no-image.png").getInputStream(); //?
        headers.setContentType(MediaType.IMAGE_PNG);
        return new ResponseEntity<>(is.readAllBytes(), headers, HttpStatus.OK);
        
    }

    @GetMapping(value = "/image2")
    public ResponseEntity<byte[]> image2(@RequestParam(name = "fno", defaultValue = "0") BigInteger fno) throws IOException{
        File obj = fRepository.findById(fno).orElse(null);
        //log.info("objobj => {}", obj);
        HttpHeaders headers = new HttpHeaders(); // import org.springframework.http.HttpHeaders;
        if(obj != null){ // 이미지가 존재하는지 확인
            if(obj.getFsize() != null){
                headers.setContentType( MediaType.parseMediaType(obj.getFtype()));
                return new ResponseEntity<>(obj.getFdata(), headers, HttpStatus.OK);
            }
        }
        // 이미지가 없을 경우
        InputStream is = resourceLoader.getResource("./img/no-image.png").getInputStream(); //?
        headers.setContentType(MediaType.IMAGE_PNG);
        return new ResponseEntity<>(is.readAllBytes(), headers, HttpStatus.OK);
    }

    //127.0.0.1:9090/CUSTOM/product/making.do
    @GetMapping(value = "/making.do")
    public String makingGET(
            Model model, 
            @RequestParam(name="tno") long tno,
            @RequestParam(name="psno") long psno,
            HttpServletRequest request,
            @AuthenticationPrincipal MemberUser user,
            @ModelAttribute TshirtPrintingSidePicView tpspicView,
            @ModelAttribute PsidePicSorting obj,
            @RequestParam(name="typeCode", defaultValue = "0") int typeCode ){
        try {
            if(user != null){ // 로그인 되었음
                log.info("로그인user => {}", user); 
                //로그인user => MemberUser(username=aaa, authorities=[ROLE_MEMBER], name=aaa)
                }
            model.addAttribute("user", user);



            // 앞면뒷면에 따라 앞면뒷면 사진가져오기
            
            // 1. 앞면 뒷면 나오게 하기
            TshirtPrintingSidePicViewDTO psdto2 = new TshirtPrintingSidePicViewDTO();
            List<TshirtPrintingSidePicView> pspicList = tpspvRepository.findByTno(BigInteger.valueOf(tno));
            
            psdto2.setList(pspicList);
            model.addAttribute("psdto2", psdto2);

            // 2. 앞면뒷면(psno)에 따라 사진나오게 하기
            BigInteger psno1 = tpspicView.getPsno();
            TshirtPrintingSidePicViewDTO psdto1 = new TshirtPrintingSidePicViewDTO();
            // psno와 tno가 일치하는 것을 찾는다
            List<TshirtPrintingSidePicView> pspic = 
                tpspvRepository.findByPsnoAndTno(psno1, BigInteger.valueOf(tno)); // 티셔츠뷰 중 일부를 호출
            // imageUrl 호출
            if( pspic != null ){ 
                for(TshirtPrintingSidePicView tmp : pspic){
                    tmp.setImageUrl(request.getContextPath() + "/product/psidepic?pspicno=" + tmp.getPspicno());
                }
            }

            psdto1.setList(pspic);
            model.addAttribute("psdto1", psdto1);
            //log.info("tno로 가져온 뷰 정보 => {}", psdto1.toString());

            model.addAttribute("search", obj);

            // 앞면도 뒷면도 없을때 (처음 화면에 들어갔을때)
            if(psno > 0){
                model.addAttribute("psno", psno);
            }
            else{
                model.addAttribute("psno", 1);
            }


            // 컬러(콤보박스)
            TshirtColorDTO tcdto = new TshirtColorDTO();
            List<TshirtColor> tclist = tcRepository.findByTshirt_tno(BigInteger.valueOf(tno));
            tcdto.setList(tclist);
            //log.info("컬러정보 => {}", tclist.toString());

            // 프린팅방식 printing 테이블의 pmethod를 가져옴
            PrintingDTO pdto = new PrintingDTO();
            List<Printing> plist = pRepository.findAll();
            pdto.setList(plist);

            // 사이즈
            TshirtSizeDTO tsdto = new TshirtSizeDTO(); // select에서 사용해야하는 selectsize변수와 List<TshirtSize> list가 들어가 있는 TshirtSizeDTO
            List<TshirtSize> list = tsRepository.findByTshirt_tno(BigInteger.valueOf(tno));
            tsdto.setList(list); // 위에서 생성한 list를 tsdto의 list에 set해 준다
            //log.info("티셔츠사이즈정보 => {}", list.toString()); // 모든 정보가 나옴

            // 티셔츠 INFO
            TshirtContentView tcvobj = tcvRepository.findByTno(BigInteger.valueOf(tno));

            // 티셔츠 전체이미지 가져오기
            List<String> imageList = new ArrayList<>();
            List<TshirtImage> list1 = tiRepository.findByTshirt_tnoOrderByInoAsc(BigInteger.valueOf(tno));
            // log.info("what=> {}", list1.toString());
            if( !list1.isEmpty() ){ // 리스트 비어있지 않은ㅇ지 확인
                for(TshirtImage tmp : list1){
                    //127.0.0.1:9090/CUSTOM/product/image?ino=1
                    imageList.add( request.getContextPath() + "/product/image?ino=" + tmp.getIno() );
                }
            }
            // log.info("이미지리스트 => {}", imageList); (성공)

            model.addAttribute("tno", tno);

            model.addAttribute("imageList", imageList);

            model.addAttribute("tcdto", tcdto);
            model.addAttribute("tclist", tclist);

            model.addAttribute("pdto", pdto);
            model.addAttribute("plist", plist);

            model.addAttribute("tsdto", tsdto);
            model.addAttribute("obj", list);

            model.addAttribute("tcvobj", tcvobj);
            return "product/making";
        } catch (Exception e) {
            e.printStackTrace();
            return "redirect:/home.do";
        }
    }
    
    @GetMapping(value = "/making1.do")
    public String making1GET(
            Model model,
            HttpServletRequest request,
            @AuthenticationPrincipal MemberUser user,
            @RequestParam(name="tno") long tno,
            @RequestParam(name="psno") long psno,
            @RequestParam(name="dno") long dno
    ){
        try {
            if(user != null){ // 로그인 되었음
                log.info("로그인user => {}", user); 
                //로그인user => MemberUser(username=aaa, authorities=[ROLE_MEMBER], name=aaa)
                }
            model.addAttribute("user", user);

            // log.info("dno => {}", dno);


            // 앞면뒷면에 따라 앞면뒷면 사진가져오기
            // 1. 앞면 뒷면 나오게 하기
            TshirtPrintingSidePicViewDTO psdto2 = new TshirtPrintingSidePicViewDTO();
            List<TshirtPrintingSidePicView> pspicList = tpspvRepository.findByTno(BigInteger.valueOf(tno));
            // log.info("pspicList => {}", pspicList);
            psdto2.setList(pspicList);
            // log.info("psdto2 => {}", psdto2);
            model.addAttribute("psdto2", psdto2);

            TshirtPrintingSidePicViewDTO psdto1 = new TshirtPrintingSidePicViewDTO();
            List<TshirtPrintingSidePicView> tpspicView1 =  tpspvRepository.findByPsnoAndTno(BigInteger.valueOf(psno),  BigInteger.valueOf(tno));
            // log.info("앞뒤 => {}", tpspicView1.toString());
            model.addAttribute("tpspicView1", tpspicView1);

            // imageUrl 호출
            if( tpspicView1 != null ){ 
                for(TshirtPrintingSidePicView tmp : tpspicView1){
                    tmp.setImageUrl(request.getContextPath() + "/product/psidepic?pspicno=" + tmp.getPspicno());
                }
            }
            
            psdto1.setList(tpspicView1);
            // log.info("psdto1 => {}", psdto1.toString());
            model.addAttribute("psdto1", psdto1);

            DesignOne dOne = dOneRepository.findByDno(BigInteger.valueOf(dno));
            // log.info("디자인정보 =>{}", dOne);
            model.addAttribute("dOne", dOne);

            // 컬러(콤보박스)
            TshirtColorDTO tcdto = new TshirtColorDTO();
            List<TshirtColor> tclist = tcRepository.findByTshirt_tno(BigInteger.valueOf(tno));
            tcdto.setList(tclist);
            model.addAttribute("tcdto", tcdto);
            //log.info("컬러정보 => {}", tclist.toString());

            // 프린팅방식 printing 테이블의 pmethod를 가져옴
            PrintingDTO pdto = new PrintingDTO();
            List<Printing> plist = pRepository.findAll();
            pdto.setList(plist);
            model.addAttribute("pdto", pdto);
            // log.info("프린팅방식 => {}", pdto);

            // 사이즈
            TshirtSizeDTO tsdto = new TshirtSizeDTO(); // select에서 사용해야하는 selectsize변수와 List<TshirtSize> list가 들어가 있는 TshirtSizeDTO
            List<TshirtSize> list = tsRepository.findByTshirt_tno(BigInteger.valueOf(tno));
            tsdto.setList(list); // 위에서 생성한 list를 tsdto의 list에 set해 준다
            model.addAttribute("tsdto", tsdto);
            //log.info("티셔츠사이즈정보 => {}", list.toString()); // 모든 정보가 나옴

            // 티셔츠 전체이미지 가져오기
            List<String> imageList = new ArrayList<>();
            List<TshirtImage> list1 = tiRepository.findByTshirt_tnoOrderByInoAsc(BigInteger.valueOf(tno));
            // log.info("what=> {}", list1.toString());
            if( !list1.isEmpty() ){ // 리스트 비어있지 않은ㅇ지 확인
                for(TshirtImage tmp : list1){
                    //127.0.0.1:9090/CUSTOM/product/image?ino=1
                    imageList.add( request.getContextPath() + "/product/image?ino=" + tmp.getIno() );
                }
            }
            model.addAttribute("imageList", imageList);

             // 티셔츠 INFO
            TshirtContentView tcvobj = tcvRepository.findByTno(BigInteger.valueOf(tno));
            model.addAttribute("tcvobj", tcvobj);

            return "product/making1";
        } catch (Exception e) {
            e.printStackTrace();
            return "home";
        }
    }

    // 127.0.0.1:9090/CUSTOM/product/making.do
    @PostMapping(value = "/design.do")
    public String makingPOST(
        @RequestParam(name = "tno") long tno,
        @AuthenticationPrincipal MemberUser user,
        @RequestParam(name = "psno") long psno,
        @RequestParam(name = "selectpmethod") String selectpmethod,
        @RequestParam(name = "selectcolor") String selectcolor,
        @RequestParam(name = "selectsize") String selectsize,

        @ModelAttribute File obj,
        @RequestParam(name = "file1") MultipartFile file1,

        @ModelAttribute TsDesignView tsdv,
        @ModelAttribute Tshirt tshirt,

        @ModelAttribute File file2,
        @ModelAttribute Printing printing,
        @ModelAttribute PrintingSide printingSide,
        
        @ModelAttribute DesignOne dOne
        // @RequestParam(name="mid") String mid
        // @AuthenticationPrincipal MemberUser user
        ){
        try {
            
            obj.setFname(file1.getOriginalFilename());
            obj.setFsize(BigInteger.valueOf(file1.getSize()));
            obj.setFtype(file1.getContentType());
            obj.setFdata(file1.getInputStream().readAllBytes());
            // log.info("파일정보 => {}", obj.toString());
            fRepository.save(obj);
            
            // 컬러 사이즈
            TshirtView01 tView01 = tView01Repository.findByTcolornameAndTnoAndTssize(selectcolor, BigInteger.valueOf(tno), selectsize );
            // 프린팅 방식
            Printing printing1 = pRepository.findByPmethod(selectpmethod);
            //log.info("컬러 사이즈 => {}",tView01);

            if(user.getUsername() == null){
                return "redirect:/login.do";
            }
            Member member = mRepository.findByMid(user.getUsername());

            // Member member = new Member();
            printing.setPno(printing1.getPno());
            file2.setFno(obj.getFno());
            printingSide.setPsno(BigInteger.valueOf(psno));
            tshirt.setTno(tView01.getTno());

            dOne.setFile(file2);
            dOne.setTshirt(tshirt); // 여기에 컬러랑 사이즈랑 프린팅방식이 안담기지 않나 //
            dOne.setPrintingSide(printingSide);
            dOne.setPrinting(printing);
            dOne.setMember(member);
            dOne.setTcolorno(tView01.getTcolorno());
            dOne.setTsno(tView01.getTsno());
            log.info("디자인원111 => {}", dOne.toString());
            
            dOneRepository.save(dOne);
            // + "&tcolorno=" + tView01.getTcolorno() + "&tsno=" + tView01.getTsno()
            return "redirect:/product/order.do?tno=" + tno + 
                                            "&psno=" + psno + 
                                            "&tcolorno=" + tView01.getTcolorno() + 
                                            "&tsno=" + tView01.getTsno() + 
                                            "&pno=" + printing.getPno() + 
                                            "&fno=" + obj.getFno() + 
                                            "&mid=" + member.getMid();
        } catch (Exception e) {
            e.printStackTrace();
            return "redirect:/home.do";
        }
    }

    // 127.0.0.1:9090/CUSTOM/product/making.do
    @PostMapping(value = "/design1.do")
    public String making1POST(
        @RequestParam(name = "tno") long tno,
        @RequestParam(name = "psno") long psno,
        @RequestParam(name = "printing.pmethod") String pmethod,
        @RequestParam(name = "selectcolor") String selectcolor,
        @RequestParam(name = "selectsize") String selectsize,

        @ModelAttribute File obj,
        @RequestParam(name = "file1") MultipartFile file1,

        @ModelAttribute TsDesignView tsdv,
        @ModelAttribute Tshirt tshirt,

        @ModelAttribute File file2,
        @ModelAttribute Printing printing,
        @ModelAttribute PrintingSide printingSide,
        
        @ModelAttribute DesignOne dOne,
        @RequestParam(name="mid") String mid
    ){
        try {
            
            // log.info("pmethod => {}", pmethod);
            // 파일 저장 (파일 선택하고 업로드)
            obj.setFname(file1.getOriginalFilename());
            obj.setFsize(BigInteger.valueOf(file1.getSize()));
            obj.setFtype(file1.getContentType());
            obj.setFdata(file1.getInputStream().readAllBytes());
            // log.info("파일정보 => {}", obj.toString());
            fRepository.save(obj);

            // 컬러 사이즈
            TshirtView01 tView01 = tView01Repository.findByTcolornameAndTnoAndTssize(selectcolor, BigInteger.valueOf(tno), selectsize );
            // log.info("티셔츠뷰 => {}",tView01);
            // 프린팅 방식
            Printing printing1 = pRepository.findByPmethod(pmethod);
            Member member = mRepository.findByMid(mid);

            // Member member = new Member();
            printing.setPno(printing1.getPno());
            file2.setFno(obj.getFno());
            printingSide.setPsno(BigInteger.valueOf(psno));
            tshirt.setTno(tView01.getTno());

            dOne.setFile(file2);
            dOne.setTshirt(tshirt); // 여기에 컬러랑 사이즈랑 프린팅방식이 안담기지 않나 //
            dOne.setPrintingSide(printingSide);
            dOne.setPrinting(printing);
            dOne.setMember(member);
            log.info("디자인원222 => {}", dOne.toString());

            dOneRepository.save(dOne);

            return "redirect:/product/order.do?tno=" + tno + 
                                            "&psno=" + psno + 
                                            "&tcolorno=" + tView01.getTcolorno() + 
                                            "&tsno=" + tView01.getTsno() + 
                                            "&pno=" + printing.getPno() + 
                                            "&fno=" + obj.getFno() + 
                                            "&mid=" + mid;
        } catch (Exception e) {
            e.printStackTrace();
            return "home";
        }
    }

    @GetMapping(value = "/order.do")
    public String orderGET(Model model, 
            HttpServletRequest request,
            @AuthenticationPrincipal MemberUser user,
            @RequestParam(name="mid") String mid,
            @RequestParam(name="tsno") BigInteger tsno, // 티셔츠사이즈
            @RequestParam(name="fno") BigInteger fno, // 파일
            @RequestParam(name="pno") BigInteger pno, // 프린팅방식
            @RequestParam(name="tcolorno") BigInteger tcolorno, // 프린팅방식
            @RequestParam(name="tno") BigInteger tno,  // 티셔츠
            @RequestParam(name="psno") BigInteger psno // 프린팅사이드
            ) {
        try {
            if(user != null){ // 로그인 되었음
                log.info("로그인user => {}", user); 
                //로그인user => MemberUser(username=aaa, authorities=[ROLE_MEMBER], name=aaa)
                }
            model.addAttribute("user", user);

            // log.info("psno => {}", psno); 

            TsDesignView tsdv = tsdvRepository.selectOneTsDesignGroupByDno(mid, tno, psno, tcolorno, tsno, pno, fno);
            // log.info("tsdv => {}", tsdv); 

            model.addAttribute("tsdv", tsdv);

            DesignOne dOne = dOneRepository.findByDno(tsdv.getDno());
            PsidePic psidePic = pspRepository.findByPrintingSide_PsnoAndTshirt_Tno(psno , tno);
            File file = fRepository.findByFno(dOne.getFile().getFno());
            // PsidePic imageUrl 호출
            if( psidePic != null ){ 
                psidePic.setImageUrl2(request.getContextPath() + "/product/psidepic?pspicno=" + psidePic.getPspicno());
            }
            model.addAttribute("psidePic", psidePic);
            log.info("psidePic=> {}", psidePic);
            
            // file imageUrl 호출
            if( file != null ){ 
                file.setImageUrl1(request.getContextPath() + "/product/image2?fno=" + file.getFno());
            }
            model.addAttribute("file1", file);
            log.info("file=> {}", file);

            return "product/order";
        } catch (Exception e) {
            log.error("Exception occurred while processing order GET request", e);
            return "redirect:/home.do";
        }
    }

    @GetMapping(value = "/order1.do")
    public String order1GET(
        Model model,
        HttpServletRequest request,
        @AuthenticationPrincipal MemberUser user,
        @RequestParam(name = "ono") long ono
    ){
        try {
            if(user != null){ // 로그인 되었음
                log.info("로그인user => {}", user); 
                //로그인user => MemberUser(username=aaa, authorities=[ROLE_MEMBER], name=aaa)
                }
            model.addAttribute("user", user);

            Orders orders = ordersRepository.findByOno(BigInteger.valueOf(ono));
            TshirtColor tcolor = tcRepository.findByTcolorno(orders.getDesignOne().getTcolorno());
            orders.setTcolorname(tcolor.getTcolorname());

            TshirtSize tSize = tsRepository.findByTsno(orders.getDesignOne().getTsno());
            orders.setTssize(tSize.getTssize());

            Tshirt tshirt = tRepository.findByTno(orders.getDesignOne().getTshirt().getTno());
            orders.setTname(tshirt.getTname());
            orders.setTprice(tshirt.getTprice());

            Printing printing = pRepository.findBypno(orders.getDesignOne().getPrinting().getPno());
            orders.setPmethod(printing.getPmethod());
            orders.setPprice(printing.getPprice());

            PrintingSide pside = psRepository.findByPsno(orders.getDesignOne().getPrintingSide().getPsno());
            orders.setPsidename(pside.getPsidename());

            PsidePic psidePic = pspRepository.findByPrintingSide_PsnoAndTshirt_Tno(pside.getPsno(), tshirt.getTno());
            orders.setPspicno(psidePic.getPspicno());
            orders.setImageUrl2(psidePic.getImageUrl2());
            
            File file = fRepository.findByFno(orders.getDesignOne().getFile().getFno());
            orders.setFno(file.getFno());
            orders.setImageUrl1(file.getImageUrl1());

            model.addAttribute("orders", orders);

            // PsidePic imageUrl 호출
            if( psidePic != null ){ 
                psidePic.setImageUrl2(request.getContextPath() + "/product/psidepic?pspicno=" + psidePic.getPspicno());
            }
            model.addAttribute("psidePic", psidePic);
            log.info("psidePic=> {}", psidePic);
            
            // file imageUrl 호출
            if( file != null ){ 
                file.setImageUrl1(request.getContextPath() + "/product/image2?fno=" + file.getFno());
            }
            model.addAttribute("file1", file);
            log.info("file=> {}", file);

            return "product/order1";
        } catch (Exception e) {
            log.error("Exception occurred while processing order GET request", e);
            return "redirect:/home.do";
        }
    }

    @PostMapping(value = "/order.do")
    public String orderPOST(
            @ModelAttribute MemberAddress mAddress,
            @ModelAttribute Orders orders,
            @RequestParam(name="mid") String mid,
            HttpServletRequest request,
            @RequestParam(name = "postcode") String postcode,
            @RequestParam(name = "address") String address,
            @RequestParam(name = "detailadd") String detailadd,
            @RequestParam(name = "addextra") String addextra,
            
            @RequestParam(name = "aname") String aname,
            @RequestParam(name = "aphone") String aphone,
            @RequestParam(name = "dno") long dno,
            @RequestParam(name = "ocondition") long ocondition,
            @RequestParam(name = "ocnt") long ocnt
    ){
        try {
            // log.info("값오니 => {}", tcolorno);

            // orders :  ocnt dno o
            DesignOne designOne = dOneRepository.findByDno(BigInteger.valueOf(dno));
            orders.setOcnt(BigInteger.valueOf(ocnt));
            orders.setDesignOne(designOne);
            orders.setOcondition(BigInteger.valueOf(ocondition));

            ordersRepository.save(orders);

            // memberAddress : ANO MID ANAME APHONE APOSTCODE AADDRESS
            Member member = mRepository.findByMid(mid);
            mAddress.setMember(member);
            mAddress.setAname(aname);
            mAddress.setAphone(aphone);
            mAddress.setApostcode(postcode);
            mAddress.setAaddress(address + detailadd + addextra);

            // log.info("mAddress 값 => {}", mAddress.toString());
		
            mAddressRepository.save(mAddress);

            return "redirect:/member/mypage.do?menu=3";
        } catch (Exception e) {
            e.printStackTrace();
            return "home";
        }
    }

    @PostMapping(value = "/order1.do")
    public String order1POST(
            @ModelAttribute MemberAddress mAddress,
            @ModelAttribute Orders orders,
            @RequestParam(name="mid") String mid,
            HttpServletRequest request,

            @RequestParam(name = "postcode") String postcode,
            @RequestParam(name = "address") String address,
            @RequestParam(name = "detailadd") String detailadd,
            @RequestParam(name = "addextra") String addextra,

            @RequestParam(name = "aname") String aname,
            @RequestParam(name = "aphone") String aphone,
            @RequestParam(name = "dno") long dno,
            @RequestParam(name = "ocondition") long ocondition,
            @RequestParam(name = "ocnt") long ocnt
    ){
        try {
            // log.info("값오니 => {}", tcolorno);

            DesignOne designOne = dOneRepository.findByDno(BigInteger.valueOf(dno));
            orders.setOcnt(BigInteger.valueOf(ocnt));
            orders.setDesignOne(designOne);
            orders.setOcondition(BigInteger.valueOf(ocondition));

            ordersRepository.save(orders);

            log.info("아이디 안오냐 => {}", mid);
            // memberAddress : ANO MID ANAME APHONE APOSTCODE AADDRESS
            Member member = mRepository.findByMid(mid);
            mAddress.setMember(member);
            mAddress.setAname(aname);
            mAddress.setAphone(aphone);
            mAddress.setApostcode(postcode);
            mAddress.setAaddress(address + detailadd + addextra);
            log.info("mAddress 값 => {}", mAddress.toString());
		
            mAddressRepository.save(mAddress);

            return "redirect:/member/mypage.do?menu=3";
        } catch (Exception e) {
            return "home";
        }
    }

    // 관리자

    @GetMapping(value = "/insertimage.do")
    public String insertimageGET(Model model, @RequestParam(name="tno") long tno){
        try {
            model.addAttribute("tno", tno);
            return "product/insertimage";
        } catch (Exception e) {
            e.printStackTrace();
            return "redirect:/product.do";
        } 
    }
    @GetMapping(value = "/insertpsidepic.do")
    public String insertpsidepiGET(Model model, 
                    @RequestParam(name="tno") long tno
                    
                    ){
        try {
            
            //log.info("티엔오 => {}", tno);
            
            // 프린팅사이드에 대한 드롭다운 정보제공+
            PrintingSideDTO psdto = new PrintingSideDTO();
            List<PrintingSide> psList = psRepository.findAll();
            psdto.setList(psList);

            // model.addAttribute("obj", obj);
            model.addAttribute("psdto", psdto);
            model.addAttribute("tno", tno);
            
            //model.addAttribute("psno", psno);
            return "product/insertpsidepic";
        } catch (Exception e) {
            e.printStackTrace();
            return "redirect:/product.do";
        } 
    }

    @PostMapping(value = "/insertpsidepic.do")
    public String insertpsidepicPOST(@ModelAttribute PsidePic obj2, 
                @RequestParam(name="file2") MultipartFile file2,
                @RequestParam(name="tno") long tno,
                // @RequestParam(name="psidename") String psidename,
                @RequestParam(name="selectpside", defaultValue = "", required = false) String selectpside
                // 주소에 정보가 없어도 ㄱㄴ 
                // 근데 selectpside를 받으면 psno는 어디서 받아오지
                ){
        try {
            // psidename으로 psno를 찾아
            //log.info("프린팅사이드 => {}", selectpside.toString());
            //log.info("수ㅐ => {}", tno);
            //log.info("파일 => {}", file2.getOriginalFilename());
            // '앞면'을 이용해서 psno를 받아오기
            
            PrintingSide printingSide = psRepository.findByPsidename(selectpside);

            //log.info("프린팅사이드no => {}", printingSide.getPsno());
                
            // 파일받기
            obj2.setPspicname(file2.getOriginalFilename());
            obj2.setPspicsize(BigInteger.valueOf(file2.getSize()));
            obj2.setPspictype(file2.getContentType());
            obj2.setPspicdata(file2.getInputStream().readAllBytes());

            // obj2에는 PrintingSide가 있으니 PrintingSide를 넣어줘야한다
            // PrintingSide에 값을 넣어주려면 그 객체가 필요하다.
            obj2.setPrintingSide(printingSide);

            Tshirt tshirt = new Tshirt();
            // set넣을값 에서 컨트롤스페이스를 눌러 넣어야 할 타입을 찾은 뒤 없으면 새로 객체를 생성
            // 그리고 그 객체에 set을 통해 원하는 값을 넣어준 후 최종적으로 넣어 줘야하는 객체에 값을 넣어줘야 한다.
            tshirt.setTno(BigInteger.valueOf(tno));
            obj2.setTshirt(tshirt);
            log.info("프린팅사이드픽 정보 -> {}", obj2.toString());

            // 오류코드 : Failed to perform cleanup of multipart items :왜?
            // 톰캣을 사용해서 생기는 Caused by: java.io.IOException 오류이다
            //  서버에 올리면 사라짐

            ppRepository.save(obj2);
            
            // /selectlist.do?id=" + id +"&page=1";
            return "redirect:/product.do?tno=" + obj2.getTshirt().getTno() + "&psno=" + printingSide.getPsno();
        } catch (Exception e) {
            e.printStackTrace();
            return "redirect:/home.do";
        }
    }
    @PostMapping(value="/insertimage.do")
    public String insertimagePOST(@ModelAttribute TshirtImage obj, 
                                @RequestParam(name="file") MultipartFile file
                                ) {
        try {
            //log.info("이미지정보 => {}", obj.getTno());
            // 파일은 수동으로 obj에 추가
            obj.setIname(file.getOriginalFilename());
            obj.setIsize(BigInteger.valueOf(file.getSize()));
            // (BigInteger.valueOf(file.getSize())) : long,int -> BigInteger 형변환
            obj.setItype(file.getContentType());
            obj.setIdata(file.getInputStream().readAllBytes());
            
            tiRepository.save(obj);
            // 왜 안되지

            return "redirect:/product.do?tno=" + obj.getTshirt().getTno();
        } catch (Exception e) {
            e.printStackTrace();
            return "redirect:/home.do";
        }
    }
    
}
